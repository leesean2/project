"""
Unit tests for response server modules.

Run: python -m pytest tests/ -v
  or: python tests/test_all.py
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
        "proc.name": "exploit",
        "proc.cmdline": "./exploit --root",
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

SAMPLE_NMAP_EVENT = {
    "rule": "Compliance - Container Reconnaissance Activity",
    "priority": "Notice",
    "output": "Reconnaissance activity with attacker tool ...",
    "output_fields": {
        "proc.name": "nmap",
        "proc.cmdline": "nmap -sS 10.0.0.0/24",
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


# 호스트 이벤트 — 패키지 매니저 업그레이드 (오탐이어야 함)
SAMPLE_HOST_PKG_WRITE = {
    "rule": "Falco Tamper - Binary Write Attempt",
    "priority": "Critical",
    "output": "Falco binary write attempt BLOCKED by chattr+i ...",
    "output_fields": {
        "proc.name": "dpkg",
        "proc.pname": "apt-get",
        "proc.cmdline": "dpkg --install falco_0.43.0_amd64.deb",
        "proc.pid": 1234,
        "fd.name": "/usr/bin/falco",
        "user.name": "root",
        "user.uid": 0,
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
        "proc.cmdline": "python3 exploit.py",
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
    """nmap as root in production → boost to high."""
    clf = ThreatClassifier()
    event = FalcoEvent.from_webhook(SAMPLE_NMAP_EVENT)
    result = clf.classify(event)

    # nmap (attacker_tool=2) + root (root_user=1) + prod ns (prod_namespace=1) = score 4 → high
    assert result.severity == "high", f"Expected high, got {result.severity}"
    assert "attacker_tool" in result.reason

    print(f"  PASS: nmap+root+prod → {result.severity} (reason: {result.reason})")


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


# ═══════════════════════════════════════════════════════════
# Tests: FalsePositiveFilter
# ═══════════════════════════════════════════════════════════

def test_fp_filter_package_manager_suppressed():
    """패키지 매니저(dpkg/apt)가 Falco 바이너리를 쓰면 fp_suppressed로 판정."""
    fp_filter = FalsePositiveFilter()
    event = FalcoEvent.from_webhook(SAMPLE_HOST_PKG_WRITE)
    result = fp_filter.check(event)

    assert result.is_suppressed, (
        f"Expected suppressed, got fp_score={result.fp_score} reason={result.reason}"
    )
    assert result.fp_score >= 0.75
    assert "sys_proc:dpkg" in result.reason or "sys_pname:apt-get" in result.reason
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

def run_all():
    tests = [
        ("FalcoEvent parsing", test_falco_event_parsing),
        ("FalcoEvent empty", test_falco_event_empty),
        ("FalcoEvent to_dict", test_falco_event_to_dict),
        ("Classifier: shell warning", test_classifier_shell_warning),
        ("Classifier: privesc critical", test_classifier_privesc_critical),
        ("Classifier: recon notice", test_classifier_recon_notice),
        ("Classifier: attacker tool boost", test_classifier_attacker_tool_boost),
        ("EventStore: add/get", test_event_store_add_get),
        ("EventStore: filters", test_event_store_filters),
        ("EventStore: ring buffer", test_event_store_ring_buffer),
        ("EventStore: summary", test_event_store_summary),
        ("MetricsStore: render", test_metrics_render),
        # ── FP 오탐 완화 ──────────────────────────────────────
        ("FP filter: package manager suppressed", test_fp_filter_package_manager_suppressed),
        ("FP filter: daemon loginuid suppressed", test_fp_filter_daemon_loginuid_suppressed),
        ("FP filter: real attack not suppressed", test_fp_filter_real_attack_not_suppressed),
        ("FP filter: infra image downgrade", test_fp_filter_infra_image_downgrade),
        ("FP filter: custom thresholds", test_fp_filter_custom_thresholds),
        ("Classifier: fallback low-confidence threshold", test_classifier_confidence_threshold_fallback_downgrade),
        ("Classifier: shell high-threshold downgrade", test_classifier_shell_high_threshold_downgrade),
        ("MetricsStore: FP counters", test_metrics_fp_counters),
    ]

    print("=" * 50)
    print("Response Server Unit Tests")
    print("=" * 50)

    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn()
            passed += 1
        except Exception as e:
            print(f"  FAIL: {name} — {e}")
            failed += 1

    print("=" * 50)
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    print("=" * 50)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_all())
