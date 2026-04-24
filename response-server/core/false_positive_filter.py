"""
False Positive Filter — Response Server 2차 오탐 완화 필터.

Falco 룰을 통과한 이벤트에 대해 호스트 프로세스 패턴, 컨텍스트 신호를
기반으로 fp_score(오탐 점수)를 계산한 뒤 억제(suppress) 또는
severity 하향(downgrade) 여부를 결정한다.

fp_score 해석:
  >= suppress_threshold (기본 0.75): 이벤트 억제 → action = fp_suppressed
  >= downgrade_threshold (기본 0.45): severity 한 단계 하향
  < downgrade_threshold:             원본 severity 유지

점수 구성 요소 (호스트 이벤트):
  host_event 기본          +0.10
  proc.name 시스템 프로세스 +0.50
  proc.pname 시스템 프로세스+0.30
  loginuid 없음(데몬)       +0.25
  정상 쓰기 경로 패턴 매치  +0.35

점수 구성 요소 (컨테이너 이벤트):
  monitoring/infra 이미지  +0.20
"""

import logging
from dataclasses import dataclass

from models.events import FalcoEvent

logger = logging.getLogger("fp_filter")

# loginuid = 4294967295 (0xFFFFFFFF) — 로그인 세션 없는 커널/데몬 프로세스
_DAEMON_LOGINUID = {"4294967295", "-1", ""}

# 기본 임계값 (환경변수 FP_SUPPRESS_THRESHOLD / FP_DOWNGRADE_THRESHOLD 로 재정의)
DEFAULT_SUPPRESS_THRESHOLD = 0.75
DEFAULT_DOWNGRADE_THRESHOLD = 0.45

# ─── 호스트 시스템 프로세스 화이트리스트 ──────────────────────────────
# 이 프로세스들이 호스트에서 실행될 때 보안 이벤트 오탐 가능성이 높음
HOST_SYSTEM_PROCESSES = frozenset({
    # init / service manager
    "systemd", "systemd-journal", "systemd-udevd", "systemd-resolved",
    "systemd-logind", "systemd-networkd", "systemd-timesyncd", "init",
    # logging / audit
    "rsyslogd", "syslogd", "auditd",
    # scheduler
    "cron", "crond", "atd",
    # remote access
    "sshd", "sftp-server",
    # package managers and their child helpers
    "apt", "apt-get", "dpkg", "dpkg-preconfigure", "dpkg-reconfigure",
    "rpm", "yum", "dnf", "zypper", "apk", "pip", "pip3",
    # container runtime
    "containerd", "containerd-shim", "containerd-shim-runc-v2",
    "dockerd", "docker", "docker-proxy", "runc",
    # kubernetes
    "kubelet", "kube-proxy", "kube-apiserver",
    "kube-controller-manager", "kube-scheduler", "etcd", "coredns", "pause",
    # observability / falco itself
    "falco", "falcoctl", "falco-watchdog",
    "node-exporter", "prometheus", "grafana",
    "fluentd", "fluent-bit", "filebeat",
    # misc system services
    "snapd", "polkitd", "dbus-daemon", "NetworkManager",
    "tuned", "irqbalance", "chronyd", "ntpd",
})

# ─── 호스트에서 정상적인 (프로세스 셋, 경로 prefix 목록) 쓰기 패턴 ─────
# (proc_name 또는 proc_pname 이 프로세스 셋에 있고, fd.name 이 prefix에 매치)
HOST_NORMAL_WRITE_PATTERNS = [
    (
        frozenset({"apt", "apt-get", "dpkg", "dpkg-preconfigure", "dpkg-reconfigure"}),
        ["/var/lib/dpkg/", "/var/cache/apt/", "/var/log/apt/", "/tmp/apt"],
    ),
    (
        frozenset({"rpm", "yum", "dnf", "zypper"}),
        ["/var/lib/rpm/", "/var/cache/yum/", "/var/cache/dnf/"],
    ),
    (
        frozenset({"kubelet"}),
        ["/var/lib/kubelet/", "/etc/kubernetes/", "/run/kubelet/"],
    ),
    (
        frozenset({"containerd", "containerd-shim", "containerd-shim-runc-v2"}),
        ["/var/lib/containerd/", "/run/containerd/", "/tmp/containerd"],
    ),
    (
        frozenset({"dockerd", "docker"}),
        ["/var/lib/docker/", "/run/docker/"],
    ),
    (
        frozenset({"falco-watchdog", "touch"}),
        ["/var/run/falco-heartbeat"],
    ),
    (
        frozenset({"node-exporter", "prometheus"}),
        ["/var/lib/node_exporter/", "/var/lib/prometheus/"],
    ),
]

# ─── 오탐이 잦은 인프라/모니터링 이미지 패턴 (컨테이너 이벤트) ────────
_INFRA_IMAGE_PATTERNS = (
    "falco", "prometheus", "grafana", "fluentd", "fluent-bit",
    "node-exporter", "kube-state-metrics", "coredns",
    "calico", "weave", "cilium", "kindest", "metrics-server",
)


@dataclass
class FalsePositiveResult:
    fp_score: float           # 0.0 = 실제 위협, 1.0 = 확실한 오탐
    is_suppressed: bool       # True → action을 fp_suppressed로 강제
    downgrade_severity: bool  # True → severity 한 단계 하향
    reason: str               # 점수 산정 근거 (파이프 구분)


class FalsePositiveFilter:
    """호스트 프로세스 컨텍스트 기반 2차 오탐 필터."""

    def __init__(
        self,
        suppress_threshold: float = DEFAULT_SUPPRESS_THRESHOLD,
        downgrade_threshold: float = DEFAULT_DOWNGRADE_THRESHOLD,
    ):
        self.suppress_threshold = suppress_threshold
        self.downgrade_threshold = downgrade_threshold

    def check(self, event: FalcoEvent) -> FalsePositiveResult:
        """이벤트의 fp_score를 계산하고 억제/다운그레이드 여부를 결정."""
        fields = event.output_fields
        proc_name  = (fields.get("proc.name")    or "").strip()
        proc_pname = (fields.get("proc.pname")   or "").strip()
        fd_name    = (fields.get("fd.name")      or "").strip()
        container_id = (event.k8s.container_id   or fields.get("container.id", "") or "")
        image      = (event.k8s.image            or "").lower()
        loginuid   = str(fields.get("user.loginuid", "")).strip()

        is_host = container_id in ("host", "")
        score = 0.0
        reasons: list[str] = []

        if is_host:
            score += 0.10
            reasons.append("host_event")

            # [MEDIUM #6] proc.name 화이트리스트 단독으로 suppress 임계값(0.75)에
            # 도달하지 않도록 점수 상한을 분리 관리.
            # 공격자가 프로세스명을 "systemd"로 위장해도 proc.name 점수만으로는
            # suppress(0.75) 에 도달하지 않음 (0.10 + 0.50 = 0.60 < 0.75).
            # loginuid + 정상 쓰기 경로까지 함께 확인되어야 suppress됨.
            if proc_name in HOST_SYSTEM_PROCESSES:
                score += 0.50
                reasons.append(f"sys_proc:{proc_name}")

            if proc_pname in HOST_SYSTEM_PROCESSES:
                score += 0.30
                reasons.append(f"sys_pname:{proc_pname}")

            # loginuid=4294967295 는 커널/데몬 프로세스의 특성
            # 공격자가 위장하려면 setuid 시스콜 필요 → 별도 룰에서 탐지됨
            if loginuid in _DAEMON_LOGINUID:
                score += 0.25
                reasons.append("daemon_loginuid")

            if fd_name:
                for proc_set, path_prefixes in HOST_NORMAL_WRITE_PATTERNS:
                    if proc_name in proc_set or proc_pname in proc_set:
                        if any(fd_name.startswith(p) for p in path_prefixes):
                            score += 0.35
                            reasons.append(f"normal_write:{proc_name}->{fd_name[:40]}")
                            break

        else:
            # 컨테이너 이벤트: 인프라/모니터링 이미지 체크
            if image and any(pat in image for pat in _INFRA_IMAGE_PATTERNS):
                score += 0.20
                reasons.append(f"infra_image:{image[:40]}")

        score = round(min(score, 1.0), 3)
        is_suppressed  = score >= self.suppress_threshold
        do_downgrade   = (not is_suppressed) and (score >= self.downgrade_threshold)
        reason_str     = " | ".join(reasons) if reasons else "none"

        if is_suppressed:
            logger.info(
                "FP suppressed: rule=%s score=%.3f reason=%s",
                event.rule, score, reason_str,
            )
        elif do_downgrade:
            logger.info(
                "FP downgrade: rule=%s score=%.3f reason=%s",
                event.rule, score, reason_str,
            )

        return FalsePositiveResult(
            fp_score=score,
            is_suppressed=is_suppressed,
            downgrade_severity=do_downgrade,
            reason=reason_str,
        )
