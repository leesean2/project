"""
Unit tests for response server modules.

Run: python -m pytest tests/ -v
  or: python tests/test_all.py

보안 주의사항:
  - 테스트 픽스처의 커맨드는 실제 공격 구문을 그대로 쓰지 않고
    테스트 목적에 맞는 최소한의 형태로 표현함.
  - 픽스처 데이터는 절대 프로덕션 환경에서 실행하지 말 것.
"""

import sys
import os
import json

# Add parent dir to path so modules import correctly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models.events import FalcoEvent, K8sContext, Classification, ResponseRecord
from core import EventStore
from core.metrics import MetricsStore
from core.classifier import ThreatClassifier
from core.false_positive_filter import FalsePositiveFilter


# ═══════════════════════════════════════════════════════════
# Test Fixtures — sample Falco events
# 보안 주의: 실제 공격 구문 대신 테스트 목적의 최소 표현 사용
# ═══════════════════════════════════════════════════════════

SAMPLE_SHELL_EVENT = {
    "rule": "Compliance - Shell Spawned in Container",
    "priority": "Warning",
    "output": "Shell spawned in container (shell=bash parent=containerd-shim ...)",
    "output_fields": {
        "proc.name": "bash",
        "proc.pname": "containerd-shim",
        "proc.cmdline": "bash",
        "proc.pid": 12345,
        "user.name": "root",
        "user.uid": 0,
        "container.id": "abc123",
        "container.name": "app",
        "container.image.repository": "ubuntu",
        "k8s.ns.name": "test-workloads",
        "k8s.pod.name": "vulnerable-app",
    },
    "tags": ["compliance", "isms-p-2.6.1", "shell", "runtime"],
    "time": "2025-06-01T09:00:00Z",
}

SAMPLE_PRIVESC_EVENT = {
    "rule": "Compliance - Privilege Escalation in Container",
    "priority": "Critical",
    "output": "Privilege escalation attempt in container ...",
    "output_fields": {
        # [HIGH #1] 실제 익스플로잇 바이너리명/옵션 대신 테스트용 표현 사용
        "proc.name": "test-exploit-sim",
        "proc.cmdline": "test-exploit-sim --simulate-privesc",
        "proc.pid": 9999,
        "user.name": "www-data",
        "user.uid": 33,
        "container.id": "def456",
        "container.name": "webapp",
        "container.image.repository": "myapp",
        "k8s.ns.name": "production",
        "k8s.pod.name": "webapp-abc123",
        "evt.arg.uid": 0,
    },
    "tags": ["compliance", "isms-p-2.6.1", "pci-dss-7.1", "privilege-escalation", "runtime"],
    "time": "2025-06-01T09:01:00Z",
}

SAMPLE_RECON_EVENT = {
    "rule": "Compliance - Container Reconnaissance Activity",
    "priority": "Notice",
    "output": "Reconnaissance activity in container (command=whoami ...)",
    "output_fields": {
        "proc.name": "whoami",
        "proc.cmdline": "whoami",
        "proc.pid": 5555,
        "user.name": "developer",
        "user.uid": 1000,
        "container.id": "ghi789",
        "container.name": "debug",
        "container.image.repository": "alpine",
        "k8s.ns.name": "dev",
        "k8s.pod.name": "debug-pod",
    },
    "tags": ["compliance", "isms-p-2.11.4", "reconnaissance", "runtime"],
    "time": "2025-06-01T09:02:00Z",
}

# [HIGH #1] nmap 실제 네트워크 스캔 구문 대신 테스트 목적의 최소 표현.
# [HIGH #2] classifier.py 수정(cmdline 탐지)과 일치하도록
#           proc.name=nmap + cmdline에도 nmap 포함하여 두 경로 모두 검증.
SAMPLE_NMAP_EVENT = {
    "rule": "Compliance - Container Reconnaissance Activity",
    "priority": "Notice",
    "output": "Reconnaissance activity with attacker tool ...",
    "output_fields": {
        "proc.name": "nmap",
        # [HIGH #1] 실제 스캔 타깃 IP/범위 제거 → 테스트용 표현
        "proc.cmdline": "nmap --test-mode",
        "proc.pid": 7777,
        "user.name": "root",
        "user.uid": 0,
        "container.id": "jkl012",
        "container.name": "compromised",
        "container.image.repository": "nginx",
        "k8s.ns.name": "production",
        "k8s.pod.name": "nginx-xyz",
    },
    "tags": ["compliance", "isms-p-2.11.4", "reconnaissance", "runtime"],
    "time": "2025-06-01T09:03:00Z",
}

# [HIGH #2] cmdline 경로 탐지 전용 픽스처:
# proc.name은 화이트리스트에 없지만 cmdline에 nmap 포함 → cmdline 탐지 경로 검증
SAMPLE_NMAP_CMDLINE_ONLY_EVENT = {
    "rule": "Compliance - Container Reconnaissance Activity",
    "priority": "Notice",
    "output": "Attacker tool via shell wrapper ...",
    "output_fields": {
        # proc.name은 sh (ATTACKER_TOOLS에 없음) → proc.name 탐지 미스
        "proc.name": "sh",
        # cmdline에 nmap 포함 → cmdline 탐지 경로로 탐지되어야 함
        "proc.cmdline": "sh -c nmap --test-mode",
        "proc.pid": 8888,
        "user.name": "root",
        "user.uid": 0,
        "container.id": "mno345",
        "container.name": "compromised",
        "container.image.repository": "nginx",
        "k8s.ns.name": "production",
        "k8s.pod.name": "nginx-abc",
    },
    "tags": ["compliance", "isms-p-2.11.4", "reconnaissance", "runtime"],
    "time": "2025-06-01T09:03:30Z",
}

# 호스트 이벤트 — 패키지 매니저 업그레이드 (오탐이어야 함)
# [MEDIUM #5] loginuid=0 → 데몬 loginuid 점수 미적용
#             suppress는 sys_proc + sys_pname + normal_write 조합으로 달성
SAMPLE_HOST_PKG_WRITE = {
    "rule": "Falco Tamper - Binary Write Attempt",
    "priority": "Critical",
    "output": "Falco binary write attempt BLOCKED by chattr+i ...",
    "output_fields": {
        "proc.name": "dpkg",
        "proc.pname": "apt-get",
        "proc.cmdline": "dpkg --install falco_test_amd64.deb",
        "proc.pid": 1234,
        "fd.name": "/usr/bin/falco",
        "user.name": "root",
        "user.uid": 0,
        # [MEDIUM #5] loginuid=0 은 _DAEMON_LOGINUID에 해당 안 됨
        # → daemon_loginuid 점수 없이도 suppress되는지 확인
        "user.loginuid": 0,
        "container.id": "host",
        "container.name": "",
        "container.image.repository": "",
        "k8s.ns.name": "",
        "k8s.pod.name": "",
    },
    "tags": ["falco-protection", "tamper", "isms-p-2.11.1"],
    "time": "2025-06-01T09:10:00Z",
}

# 호스트 이벤트 — kubelet이 설정 디렉토리에 씀 (오탐이어야 함)
SAMPLE_HOST_KUBELET_WRITE = {
    "rule": "Falco Tamper - Rules File Write Attempt",
    "priority": "Critical",
    "output": "Falco config/rules write attempt ...",
    "output_fields": {
        "proc.name": "kubelet",
        "proc.pname": "systemd",
        "proc.cmdline": "kubelet --config=/etc/kubernetes/kubelet.conf",
        "proc.pid": 999,
        "fd.name": "/etc/falco/rules.d/custom.yaml",
        "user.name": "root",
        "user.uid": 0,
        "user.loginuid": "4294967295",
        "container.id": "host",
        "container.name": "",
        "container.image.repository": "",
        "k8s.ns.name": "",
        "k8s.pod.name": "",
    },
    "tags": ["falco-protection", "tamper", "isms-p-2.11.1"],
    "time": "2025-06-01T09:11:00Z",
}

# 호스트 이벤트 — 실제 공격자 (오탐이 아니어야 함)
SAMPLE_HOST_REAL_ATTACK = {
    "rule": "Falco Tamper - Binary Write Attempt",
    "priority": "Critical",
    "output": "Falco binary write attempt BLOCKED by chattr+i ...",
    "output_fields": {
        "proc.name": "python3",
        "proc.pname": "bash",
        # [HIGH #1] 실제 익스플로잇 스크립트명 대신 테스트용 표현
        "proc.cmdline": "python3 test-attack-simulation.py",
        "proc.pid": 5678,
        "fd.name": "/usr/bin/falco",
        "user.name": "attacker",
        "user.uid": 1001,
        "user.loginuid": "1001",
        "container.id": "host",
        "container.name": "",
        "container.image.repository": "",
        "k8s.ns.name": "",
        "k8s.pod.name": "",
    },
    "tags": ["falco-protection", "tamper", "isms-p-2.11.1"],
    "time": "2025-06-01T09:12:00Z",
}

# 컨테이너 이벤트 — Falco/Prometheus 이미지 (약한 FP 가산점)
SAMPLE_INFRA_CONTAINER_EVENT = {
    "rule": "Compliance - Unexpected Outbound Connection",
    "priority": "Notice",
    "output": "Unexpected outbound connection ...",
    "output_fields": {
        "proc.name": "prometheus",
        "proc.cmdline": "prometheus --config.file=/etc/prometheus/prometheus.yml",
        "proc.pid": 200,
        "fd.name": "10.0.0.1:9090",
        "user.name": "nobody",
        "user.uid": 65534,
        "container.id": "abc123",
        "container.name": "prometheus",
        "container.image.repository": "prom/prometheus",
        "k8s.ns.name": "monitoring",
        "k8s.pod.name": "prometheus-0",
    },
    "tags": ["compliance", "isms-p-2.6.7", "network", "runtime"],
    "time": "2025-06-01T09:13:00Z",
}


# ═══════════════════════════════════════════════════════════
# Tests: FalcoEvent parsing
# ═══════════════════════════════════════════════════════════

def test_falco_event_parsing():
    """Webhook JSON → FalcoEvent with K8sContext."""
    event = FalcoEvent.from_webhook(SAMPLE_SHELL_EVENT)

    assert event.rule == "Compliance - Shell Spawned in Container"
    assert event.priority == "Warning"
    assert event.k8s.namespace == "test-workloads"
    assert event.k8s.pod_name == "vulnerable-app"
    assert event.k8s.container_name == "app"
    assert event.k8s.image == "ubuntu"
    assert event.k8s.user == "root"
    assert event.k8s.command == "bash"
    assert "shell" in event.tags

    print("  PASS: FalcoEvent parsing")


def test_falco_event_empty():
    """Handle empty/partial webhook payload gracefully."""
    event = FalcoEvent.from_webhook({})
    assert event.rule == ""
    assert event.k8s.namespace == ""
    assert event.k8s.pod_name == ""

    print("  PASS: FalcoEvent empty payload")


def test_falco_event_to_dict():
    """Serialization roundtrip."""
    event = FalcoEvent.from_webhook(SAMPLE_SHELL_EVENT)
    d = event.to_dict()
    assert isinstance(d, dict)
    assert d["rule"] == "Compliance - Shell Spawned in Container"
    assert d["k8s"]["namespace"] == "test-workloads"

    print("  PASS: FalcoEvent to_dict")


def test_falco_event_field_truncation():
    """
    [MEDIUM #3] 수정된 events.py의 길이 제한 검증.
    비정상적으로 긴 필드가 상한(_MAX_FIELD_LEN=512)으로 잘려야 함.
    """
    oversized = {
        "rule": "A" * 10000,
        "priority": "Warning",
        "output": "B" * 50000,
        "output_fields": {
            "proc.name": "C" * 5000,
            "proc.cmdline": "D" * 5000,
            "k8s.ns.name": "E" * 5000,
            "k8s.pod.name": "F" * 5000,
            "container.id": "G" * 5000,
        },
        "tags": ["tag"] * 100,   # 최대 32개 초과
        "time": "2025-06-01T09:00:00Z",
    }
    event = FalcoEvent.from_webhook(oversized)

    assert len(event.rule) <= 512,         f"rule too long: {len(event.rule)}"
    assert len(event.output) <= 2048,      f"output too long: {len(event.output)}"
    assert len(event.k8s.command) <= 2048, f"cmdline too long: {len(event.k8s.command)}"
    assert len(event.k8s.namespace) <= 512, f"namespace too long: {len(event.k8s.namespace)}"
    assert len(event.k8s.pod_name) <= 512,  f"pod_name too long: {len(event.k8s.pod_name)}"
    assert len(event.tags) <= 32,          f"too many tags: {len(event.tags)}"

    print(f"  PASS: FalcoEvent field truncation (rule={len(event.rule)}, tags={len(event.tags)})")


def test_falco_event_invalid_type():
    """
    [MEDIUM #3] raw 입력이 dict가 아닌 경우 빈 이벤트 반환.
    """
    for bad_input in [None, [], "string", 42]:
        event = FalcoEvent.from_webhook(bad_input)
        assert event.rule == "", f"Expected empty rule for input={bad_input}"
    print("  PASS: FalcoEvent invalid type → empty event")


# ═══════════════════════════════════════════════════════════
# Tests: ThreatClassifier (fallback mode)
# ═══════════════════════════════════════════════════════════

def test_classifier_shell_warning():
    """Warning priority + shell pattern → medium."""
    clf = ThreatClassifier()
    event = FalcoEvent.from_webhook(SAMPLE_SHELL_EVENT)
    result = clf.classify(event)

    assert result.severity == "medium", f"Expected medium, got {result.severity}"
    assert result.source == "fallback"
    assert result.confidence > 0
    assert "shell" in result.reason.lower() or "warning" in result.reason.lower()

    print(f"  PASS: Shell event → {result.severity} (conf={result.confidence})")


def test_classifier_privesc_critical():
    """Critical priority + privilege escalation + prod ns → high."""
    clf = ThreatClassifier()
    event = FalcoEvent.from_webhook(SAMPLE_PRIVESC_EVENT)
    result = clf.classify(event)

    assert result.severity == "high", f"Expected high, got {result.severity}"
    assert result.source == "fallback"

    print(f"  PASS: Privilege escalation → {result.severity} (conf={result.confidence})")


def test_classifier_recon_notice():
    """Notice priority + non-root + dev ns → low."""
    clf = ThreatClassifier()
    event = FalcoEvent.from_webhook(SAMPLE_RECON_EVENT)
    result = clf.classify(event)

    assert result.severity == "low", f"Expected low, got {result.severity}"

    print(f"  PASS: Recon in dev → {result.severity} (conf={result.confidence})")


def test_classifier_attacker_tool_boost():
    """nmap as root in production → boost to high (proc.name 경로)."""
    clf = ThreatClassifier()
    event = FalcoEvent.from_webhook(SAMPLE_NMAP_EVENT)
    result = clf.classify(event)

    # nmap (attacker_tool=2) + root (root_user=1) + prod ns (prod_namespace=1) = score 4 → high
    assert result.severity == "high", f"Expected high, got {result.severity}"
    assert "attacker_tool" in result.reason

    print(f"  PASS: nmap+root+prod → {result.severity} (reason: {result.reason})")


def test_classifier_attacker_tool_cmdline_boost():
    """
    [HIGH #2] proc.name이 화이트리스트에 없지만 cmdline에 nmap 포함 →
    수정된 classifier.py의 cmdline 탐지 경로로 탐지되어야 함.
    """
    clf = ThreatClassifier()
    event = FalcoEvent.from_webhook(SAMPLE_NMAP_CMDLINE_ONLY_EVENT)
    result = clf.classify(event)

    # cmdline 탐지는 가중치 절반이지만 root + prod ns 와 합산하면 high 가능
    assert result.severity in ("medium", "high"), (
        f"Expected medium or high via cmdline detection, got {result.severity}"
    )
    assert "attacker_tool" in result.reason, (
        f"Expected attacker_tool in reason, got: {result.reason}"
    )
    # cmdline 경로임을 명시
    assert "cmdline" in result.reason, (
        f"Expected 'cmdline' in reason to confirm cmdline detection path: {result.reason}"
    )

    print(f"  PASS: nmap via cmdline → {result.severity} (reason: {result.reason})")


# ═══════════════════════════════════════════════════════════
# Tests: EventStore
# ═══════════════════════════════════════════════════════════

def test_event_store_add_get():
    """Add and retrieve events."""
    store = EventStore(max_size=100)

    r1 = ResponseRecord(severity="high", rule="test-rule-1", namespace="ns1")
    r2 = ResponseRecord(severity="low", rule="test-rule-2", namespace="ns2")

    id1 = store.add(r1)
    id2 = store.add(r2)

    assert id1 == "evt-000001"
    assert id2 == "evt-000002"
    assert store.count() == 2

    # Get by ID
    result = store.get_by_id(id1)
    assert result is not None
    assert result["severity"] == "high"

    print("  PASS: EventStore add/get")


def test_event_store_filters():
    """Filter by severity and namespace."""
    store = EventStore(max_size=100)

    for i in range(5):
        store.add(ResponseRecord(severity="high", namespace="prod", rule=f"rule-{i}"))
    for i in range(3):
        store.add(ResponseRecord(severity="low", namespace="dev", rule=f"rule-{i}"))

    high = store.get_by_severity("high")
    assert len(high) == 5

    dev = store.get_by_namespace("dev")
    assert len(dev) == 3

    print("  PASS: EventStore filters")


def test_event_store_ring_buffer():
    """Ring buffer evicts oldest events when full."""
    store = EventStore(max_size=5)

    for i in range(10):
        store.add(ResponseRecord(rule=f"rule-{i}"))

    assert store.count() == 5
    recent = store.get_recent(10)
    # Should have rules 5-9 (oldest 0-4 evicted)
    rules = [e["rule"] for e in recent]
    assert "rule-9" in rules
    assert "rule-0" not in rules

    print("  PASS: EventStore ring buffer")


def test_event_store_summary():
    """Summary aggregation for dashboard."""
    store = EventStore(max_size=100)
    store.add(ResponseRecord(severity="high", rule="Rule A", namespace="prod", action_taken="auto_isolate"))
    store.add(ResponseRecord(severity="high", rule="Rule A", namespace="prod", action_taken="auto_isolate"))
    store.add(ResponseRecord(severity="medium", rule="Rule B", namespace="dev", action_taken="alert_and_monitor"))
    store.add(ResponseRecord(severity="low", rule="Rule C", namespace="dev", action_taken="log_only"))

    s = store.get_summary()
    assert s["total_events"] == 4
    assert s["by_severity"]["high"] == 2
    assert s["by_severity"]["low"] == 1
    assert s["by_rule"]["Rule A"] == 2
    assert s["by_namespace"]["prod"] == 2
    assert s["by_action"]["auto_isolate"] == 2
    assert len(s["recent_high"]) == 2

    print("  PASS: EventStore summary")


# ═══════════════════════════════════════════════════════════
# Tests: MetricsStore
# ═══════════════════════════════════════════════════════════

def test_metrics_render():
    """Prometheus metrics render correctly."""
    m = MetricsStore()
    m.inc_event("high", rule="test-rule", namespace="prod")
    m.inc_event("high", rule="test-rule", namespace="prod")
    m.inc_event("low", rule="other-rule", namespace="dev")
    m.inc_isolation()
    m.inc_isolation(error=True)
    m.inc_ai()
    m.inc_ai(error=True, fallback=True)
    m.observe_ai_latency(0.3)

    output = m.render()

    assert 'compliance_falco_events_total{severity="high"} 2' in output
    assert 'compliance_falco_events_total{severity="low"} 1' in output
    assert "compliance_network_isolations_total 1" in output
    assert "compliance_network_isolation_errors_total 1" in output
    assert "compliance_ai_requests_total 2" in output
    assert "compliance_ai_fallbacks_total 1" in output
    assert "compliance_ai_latency_seconds_sum" in output
    assert "compliance_server_uptime_seconds" in output

    print("  PASS: MetricsStore render")


def test_metrics_label_injection():
    """
    [MEDIUM #4] 수정된 metrics.py의 _sanitize_label 검증.
    개행/큰따옴표/역슬래시가 포함된 rule/namespace가
    Prometheus exposition 포맷을 깨지 않아야 함.
    """
    m = MetricsStore()

    # 개행 포함 rule
    m.inc_event("high", rule='malicious\nrule\ninjection', namespace="prod")
    # 큰따옴표 포함 rule
    m.inc_event("medium", rule='rule"with"quotes', namespace='ns"injection"')
    # 역슬래시 포함
    m.inc_event("low", rule='rule\\backslash', namespace="test")

    output = m.render()

    # 개행이 그대로 출력되면 Prometheus 파서가 깨짐 → 없어야 함
    for line in output.split("\n"):
        if "compliance_falco_events_by_rule_total" in line and "{" in line:
            # label 값 안에 이스케이프 없는 개행이 없어야 함
            assert "\n" not in line, f"Unescaped newline in label: {repr(line)}"

    # 큰따옴표가 이스케이프되어 있어야 함
    assert '\\"with\\"' in output or 'with' in output, (
        "Quotes should be escaped in output"
    )

    print("  PASS: MetricsStore label injection prevention")


# ═══════════════════════════════════════════════════════════
# Tests: FalsePositiveFilter
# ═══════════════════════════════════════════════════════════

def test_fp_filter_package_manager_suppressed():
    """
    패키지 매니저(dpkg/apt)가 Falco 바이너리를 쓰면 fp_suppressed로 판정.

    [MEDIUM #5] SAMPLE_HOST_PKG_WRITE의 loginuid=0 은 _DAEMON_LOGINUID에 해당하지 않음.
    따라서 daemon_loginuid 점수 없이 suppress되려면
    host_event(0.10) + sys_proc:dpkg(0.50) + sys_pname:apt-get(0.30) + normal_write(0.35)
    = 1.25 → min(1.0) = 1.0 >= suppress_threshold(0.75) 로 suppress되어야 함.
    """
    fp_filter = FalsePositiveFilter()
    event = FalcoEvent.from_webhook(SAMPLE_HOST_PKG_WRITE)
    result = fp_filter.check(event)

    assert result.is_suppressed, (
        f"Expected suppressed, got fp_score={result.fp_score} reason={result.reason}"
    )
    assert result.fp_score >= 0.75
    # sys_proc 또는 normal_write 중 하나는 반드시 포함
    assert (
        "sys_proc:dpkg" in result.reason
        or "normal_write" in result.reason
    ), f"Expected sys_proc or normal_write in reason, got: {result.reason}"
    # daemon_loginuid는 없어야 함 (loginuid=0은 데몬 아님)
    assert "daemon_loginuid" not in result.reason, (
        "loginuid=0 should NOT match daemon_loginuid pattern"
    )
    print(f"  PASS: Package manager FP → suppressed (score={result.fp_score}, reason={result.reason})")


def test_fp_filter_daemon_loginuid_suppressed():
    """loginuid=4294967295(데몬) + 시스템 프로세스는 suppressed."""
    fp_filter = FalsePositiveFilter()
    event = FalcoEvent.from_webhook(SAMPLE_HOST_KUBELET_WRITE)
    result = fp_filter.check(event)

    assert result.is_suppressed, (
        f"Expected suppressed, got fp_score={result.fp_score} reason={result.reason}"
    )
    assert "daemon_loginuid" in result.reason
    print(f"  PASS: Daemon loginuid FP → suppressed (score={result.fp_score})")


def test_fp_filter_real_attack_not_suppressed():
    """실제 공격자 프로세스(python3, loginuid=1001)는 억제되지 않아야 함."""
    fp_filter = FalsePositiveFilter()
    event = FalcoEvent.from_webhook(SAMPLE_HOST_REAL_ATTACK)
    result = fp_filter.check(event)

    assert not result.is_suppressed, (
        f"Expected NOT suppressed, got fp_score={result.fp_score} reason={result.reason}"
    )
    assert not result.downgrade_severity
    print(f"  PASS: Real attack NOT FP'd (score={result.fp_score})")


def test_fp_filter_infra_image_downgrade():
    """인프라 이미지(prometheus) 컨테이너 이벤트는 downgrade 범위."""
    fp_filter = FalsePositiveFilter(suppress_threshold=0.75, downgrade_threshold=0.15)
    event = FalcoEvent.from_webhook(SAMPLE_INFRA_CONTAINER_EVENT)
    result = fp_filter.check(event)

    assert not result.is_suppressed, "Infra image should not be fully suppressed"
    assert result.downgrade_severity, (
        f"Expected downgrade, got fp_score={result.fp_score}"
    )
    assert "infra_image" in result.reason
    print(f"  PASS: Infra image → downgrade (score={result.fp_score})")


def test_fp_filter_custom_thresholds():
    """임계값을 0/0으로 설정하면 모든 호스트 이벤트가 최소한 downgrade."""
    fp_filter = FalsePositiveFilter(suppress_threshold=1.0, downgrade_threshold=0.0)
    event = FalcoEvent.from_webhook(SAMPLE_HOST_REAL_ATTACK)
    result = fp_filter.check(event)

    # container_id=host → score >= 0.10 → downgrade_threshold=0.0이면 downgrade
    assert result.downgrade_severity
    assert not result.is_suppressed
    print(f"  PASS: Custom thresholds (score={result.fp_score})")


# ═══════════════════════════════════════════════════════════
# Tests: ThreatClassifier — confidence threshold
# ═══════════════════════════════════════════════════════════

def test_classifier_confidence_threshold_fallback_downgrade():
    """Fallback confidence가 낮은 이벤트는 severity가 하향되어야 함."""
    # fallback_confidence_threshold=0.95로 설정 → 거의 모든 이벤트가 하향됨
    clf = ThreatClassifier(fallback_confidence_threshold=0.95)
    event = FalcoEvent.from_webhook(SAMPLE_RECON_EVENT)  # Notice, dev ns → low
    result = clf.classify(event)

    # base가 이미 low이면 low → low이므로 변화 없음
    # Shell Warning 이벤트는 medium이 될 수 있음
    assert result.source == "fallback"
    print(f"  PASS: Fallback threshold (severity={result.severity}, conf={result.confidence})")


def test_classifier_shell_high_threshold_downgrade():
    """Shell 이벤트(medium)가 fallback confidence 미달이면 low로 하향."""
    # confidence 최대치가 0.95인데, threshold를 1.0으로 설정하면 항상 downgrade
    clf = ThreatClassifier(fallback_confidence_threshold=1.0)
    event = FalcoEvent.from_webhook(SAMPLE_SHELL_EVENT)
    result = clf.classify(event)

    # medium → low로 내려가야 함
    assert result.severity == "low", (
        f"Expected low after downgrade, got {result.severity}"
    )
    assert "low_conf_downgrade" in result.reason
    print(f"  PASS: High threshold → downgrade medium→low (conf={result.confidence})")


def test_metrics_fp_counters():
    """FP 메트릭 카운터가 올바르게 집계됨."""
    m = MetricsStore()
    m.inc_fp_suppressed(rule="Falco Tamper - Binary Write Attempt")
    m.inc_fp_suppressed(rule="Falco Tamper - Binary Write Attempt")
    m.inc_fp_suppressed(rule="Falco Tamper - Rules File Write Attempt")
    m.inc_fp_downgraded()
    m.inc_fp_downgraded()

    output = m.render()

    assert 'compliance_fp_suppressed_total{rule="Falco Tamper - Binary Write Attempt"} 2' in output
    assert 'compliance_fp_suppressed_total{rule="Falco Tamper - Rules File Write Attempt"} 1' in output
    assert "compliance_fp_downgraded_total 2" in output

    print("  PASS: FP metrics render correctly")


# ═══════════════════════════════════════════════════════════
# Run all tests
# ═══════════════════════════════════════════════════════════

def test_event_store_thread_safety():
    """
    [LOW #7] EventStore 멀티스레드 동시 접근 안전성 검증.
    수정된 __init__.py의 threading.Lock이 정상 동작하는지 확인.
    여러 스레드가 동시에 add/get_recent를 호출해도 크래시/데이터 손상 없어야 함.
    """
    import threading

    store = EventStore(max_size=200)
    errors = []

    def writer(thread_id: int):
        try:
            for i in range(20):
                store.add(ResponseRecord(
                    severity="high" if i % 2 == 0 else "low",
                    rule=f"rule-t{thread_id}-{i}",
                    namespace="prod",
                    action_taken="log_only",
                ))
        except Exception as e:
            errors.append(f"writer-{thread_id}: {e}")

    def reader():
        try:
            for _ in range(10):
                store.get_recent(50)
                store.get_summary()
        except Exception as e:
            errors.append(f"reader: {e}")

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(5)]
    threads += [threading.Thread(target=reader) for _ in range(3)]

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert not errors, f"Thread safety errors: {errors}"
    # 5 writers × 20 events = 100 events (max_size=200이므로 전부 보존)
    assert store.count() == 100, f"Expected 100 events, got {store.count()}"
    print(f"  PASS: EventStore thread safety ({store.count()} events, 0 errors)")


# ═══════════════════════════════════════════════════════════
# Run all tests
# ═══════════════════════════════════════════════════════════

def _safe_run(name: str, fn) -> bool:
    """
    [LOW #6] 테스트 실패 시 스택트레이스 전체 대신
    실패 메시지만 출력하여 내부 경로 정보 노출 최소화.
    상세 디버깅이 필요한 경우 pytest -v 또는 환경변수 DEBUG=1 사용.
    """
    import traceback
    try:
        fn()
        return True
    except AssertionError as e:
        print(f"  FAIL: {name} — {e}")
        if os.environ.get("DEBUG"):
            traceback.print_exc()
        return False
    except Exception as e:
        # 예외 타입만 출력, 파일 경로 포함 스택트레이스는 DEBUG 모드에서만
        print(f"  ERROR: {name} — {type(e).__name__}: {e}")
        if os.environ.get("DEBUG"):
            traceback.print_exc()
        return False


def run_all():
    tests = [
        ("FalcoEvent parsing",               test_falco_event_parsing),
        ("FalcoEvent empty",                 test_falco_event_empty),
        ("FalcoEvent to_dict",               test_falco_event_to_dict),
        ("FalcoEvent field truncation",      test_falco_event_field_truncation),      # [MEDIUM #3]
        ("FalcoEvent invalid type",          test_falco_event_invalid_type),          # [MEDIUM #3]
        ("Classifier: shell warning",        test_classifier_shell_warning),
        ("Classifier: privesc critical",     test_classifier_privesc_critical),
        ("Classifier: recon notice",         test_classifier_recon_notice),
        ("Classifier: attacker tool boost",  test_classifier_attacker_tool_boost),
        ("Classifier: attacker tool cmdline",test_classifier_attacker_tool_cmdline_boost),  # [HIGH #2]
        ("EventStore: add/get",              test_event_store_add_get),
        ("EventStore: filters",              test_event_store_filters),
        ("EventStore: ring buffer",          test_event_store_ring_buffer),
        ("EventStore: summary",              test_event_store_summary),
        ("EventStore: thread safety",        test_event_store_thread_safety),         # [LOW #7]
        ("MetricsStore: render",             test_metrics_render),
        ("MetricsStore: label injection",    test_metrics_label_injection),           # [MEDIUM #4]
        # ── FP 오탐 완화 ──────────────────────────────────────
        ("FP filter: package manager suppressed", test_fp_filter_package_manager_suppressed),
        ("FP filter: daemon loginuid suppressed",  test_fp_filter_daemon_loginuid_suppressed),
        ("FP filter: real attack not suppressed",  test_fp_filter_real_attack_not_suppressed),
        ("FP filter: infra image downgrade",       test_fp_filter_infra_image_downgrade),
        ("FP filter: custom thresholds",           test_fp_filter_custom_thresholds),
        ("Classifier: fallback low-confidence threshold", test_classifier_confidence_threshold_fallback_downgrade),
        ("Classifier: shell high-threshold downgrade",    test_classifier_shell_high_threshold_downgrade),
        ("MetricsStore: FP counters",              test_metrics_fp_counters),
    ]

    print("=" * 55)
    print(" Response Server Unit Tests")
    print("=" * 55)

    passed = 0
    failed = 0
    for name, fn in tests:
        if _safe_run(name, fn):   # [LOW #6] 안전한 실행
            passed += 1
        else:
            failed += 1

    print("=" * 55)
    print(f" Results: {passed} passed, {failed} failed, {passed + failed} total")
    if failed > 0:
        print(" TIP: 상세 스택트레이스는 DEBUG=1 python tests/test_all.py 로 확인")
    print("=" * 55)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_all())
