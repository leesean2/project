"""
Integration tests — starts the real HTTP server and tests end-to-end:
  Webhook POST → Processor → EventStore → API GET

Run: python tests/test_integration.py
"""

import sys
import os
import json
import time
import threading
import urllib.request
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from http.server import HTTPServer
from core import EventStore
from core.metrics import MetricsStore
from core.classifier import ThreatClassifier
from core.processor import EventProcessor
from k8s.client import KubeClient
from handlers.http import RequestHandler

# ─── Test Server Setup ────────────────────────────────────

PORT = 15123  # random high port to avoid conflicts


class TestAppServer(HTTPServer):
    def __init__(self, address, handler, processor, store, metrics, kube):
        super().__init__(address, handler)
        self.processor = processor
        self.store = store
        self.metrics = metrics
        self.kube = kube


def start_test_server():
    """Start server in background thread, return (server, thread)."""
    metrics = MetricsStore()
    store = EventStore(max_size=500)
    kube = KubeClient()  # won't connect — no cluster
    classifier = ThreatClassifier(ai_endpoint="", metrics=metrics)
    processor = EventProcessor(
        classifier=classifier, kube=kube, store=store,
        metrics=metrics, auto_isolate=False,  # disable isolation in tests
    )

    server = TestAppServer(
        ("127.0.0.1", PORT), RequestHandler,
        processor=processor, store=store, metrics=metrics, kube=kube,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)  # wait for server to bind
    return server, thread


def http_get(path: str) -> dict:
    url = f"http://127.0.0.1:{PORT}{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def http_post(path: str, body: dict) -> dict:
    url = f"http://127.0.0.1:{PORT}{path}"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def http_get_text(path: str) -> str:
    url = f"http://127.0.0.1:{PORT}{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.read().decode("utf-8")


# ─── Sample Events ────────────────────────────────────────

EVENTS = [
    {
        "rule": "Compliance - Shell Spawned in Container",
        "priority": "Warning",
        "output": "Shell spawned in container ...",
        "output_fields": {
            "proc.name": "bash", "proc.cmdline": "bash",
            "proc.pid": 100, "user.name": "appuser", "user.uid": 1000,
            "container.id": "c1", "container.name": "app",
            "container.image.repository": "ubuntu",
            "k8s.ns.name": "staging", "k8s.pod.name": "web-1",
        },
        "tags": ["compliance", "shell", "runtime"],
        "time": "2025-06-01T10:00:00Z",
    },
    {
        "rule": "Compliance - Privilege Escalation in Container",
        "priority": "Critical",
        "output": "Privilege escalation ...",
        "output_fields": {
            "proc.name": "exploit", "proc.cmdline": "./exploit",
            "proc.pid": 200, "user.name": "www-data", "user.uid": 33,
            "container.id": "c2", "container.name": "api",
            "container.image.repository": "myapi",
            "k8s.ns.name": "production", "k8s.pod.name": "api-2",
        },
        "tags": ["compliance", "privilege-escalation", "runtime"],
        "time": "2025-06-01T10:01:00Z",
    },
    {
        "rule": "Compliance - Container Reconnaissance Activity",
        "priority": "Notice",
        "output": "Recon activity ...",
        "output_fields": {
            "proc.name": "whoami", "proc.cmdline": "whoami",
            "proc.pid": 300, "user.name": "dev", "user.uid": 1000,
            "container.id": "c3", "container.name": "debug",
            "container.image.repository": "alpine",
            "k8s.ns.name": "dev", "k8s.pod.name": "debug-1",
        },
        "tags": ["compliance", "reconnaissance", "runtime"],
        "time": "2025-06-01T10:02:00Z",
    },
]


# ─── Tests ────────────────────────────────────────────────

def test_healthz(server):
    text = http_get_text("/healthz")
    assert text == "ok", f"Expected 'ok', got '{text}'"
    print("  PASS: /healthz")


def test_webhook_accepts(server):
    result = http_post("/webhook", EVENTS[0])
    assert result["status"] == "accepted"
    print("  PASS: POST /webhook → accepted")


def test_webhook_all_events(server):
    """Send all sample events and wait for processing."""
    for ev in EVENTS:
        http_post("/webhook", ev)
    time.sleep(1.0)  # wait for background processing threads
    print("  PASS: All events posted")


def test_events_api(server):
    """GET /api/v1/events should return stored events."""
    result = http_get("/api/v1/events")
    assert result["count"] >= 3, f"Expected >=3 events, got {result['count']}"
    # Events should be newest first
    events = result["events"]
    assert events[0]["rule"] == "Compliance - Container Reconnaissance Activity"
    print(f"  PASS: GET /api/v1/events → {result['count']} events")


def test_events_filter_severity(server):
    """GET /api/v1/events?severity=high"""
    result = http_get("/api/v1/events?severity=high")
    for ev in result["events"]:
        assert ev["severity"] == "high", f"Expected high, got {ev['severity']}"
    assert result["count"] >= 1
    print(f"  PASS: GET /api/v1/events?severity=high → {result['count']} events")


def test_events_filter_namespace(server):
    """GET /api/v1/events?namespace=dev"""
    result = http_get("/api/v1/events?namespace=dev")
    for ev in result["events"]:
        assert ev["namespace"] == "dev"
    print(f"  PASS: GET /api/v1/events?namespace=dev → {result['count']} events")


def test_events_summary(server):
    """GET /api/v1/events/summary"""
    result = http_get("/api/v1/events/summary")
    assert result["total_events"] >= 3
    assert "by_severity" in result
    assert "by_rule" in result
    assert "by_namespace" in result
    assert "by_action" in result
    assert "recent_high" in result
    print(f"  PASS: GET /api/v1/events/summary → total={result['total_events']}")
    print(f"         severity: {result['by_severity']}")
    print(f"         actions:  {result['by_action']}")


def test_event_by_id(server):
    """GET /api/v1/events/:id"""
    all_events = http_get("/api/v1/events")
    first_id = all_events["events"][0]["id"]
    result = http_get(f"/api/v1/events/{first_id}")
    assert result["id"] == first_id
    print(f"  PASS: GET /api/v1/events/{first_id}")


def test_event_not_found(server):
    """GET /api/v1/events/nonexistent → 404."""
    try:
        http_get("/api/v1/events/evt-999999")
        assert False, "Should have raised 404"
    except urllib.error.HTTPError as e:
        assert e.code == 404
    print("  PASS: GET /api/v1/events/nonexistent → 404")


def test_metrics(server):
    """GET /metrics returns Prometheus-format text."""
    text = http_get_text("/metrics")
    assert "compliance_falco_events_total" in text
    assert "compliance_response_actions_total" in text
    assert "compliance_ai_latency_seconds" in text
    assert "compliance_server_uptime_seconds" in text
    print("  PASS: GET /metrics → Prometheus format")


def test_webhook_invalid_json(server):
    """POST /webhook with bad JSON → 400."""
    url = f"http://127.0.0.1:{PORT}/webhook"
    req = urllib.request.Request(
        url, data=b"not json", method="POST",
        headers={"Content-Type": "application/json", "Content-Length": "8"},
    )
    try:
        urllib.request.urlopen(req, timeout=5)
        assert False, "Should have raised 400"
    except urllib.error.HTTPError as e:
        assert e.code == 400
    print("  PASS: POST /webhook invalid JSON → 400")


def test_isolations_api(server):
    """GET /api/v1/isolations (empty, no cluster)."""
    # This will return empty or error since no cluster
    # but shouldn't crash
    try:
        result = http_get("/api/v1/isolations")
        # If it responds, check structure
        assert "count" in result or "policies" in result or "error" in result
        print(f"  PASS: GET /api/v1/isolations → responded (count={result.get('count', 'n/a')})")
    except urllib.error.HTTPError:
        print("  PASS: GET /api/v1/isolations → expected error (no cluster)")


# ─── Runner ───────────────────────────────────────────────

def run_all():
    print("=" * 55)
    print(" Integration Tests (real HTTP server)")
    print("=" * 55)

    server, thread = start_test_server()
    print(f"  Server started on port {PORT}")
    print()

    tests = [
        ("Health check", test_healthz),
        ("Webhook accept", test_webhook_accepts),
        ("Post all events", test_webhook_all_events),
        ("List events", test_events_api),
        ("Filter by severity", test_events_filter_severity),
        ("Filter by namespace", test_events_filter_namespace),
        ("Event summary", test_events_summary),
        ("Event by ID", test_event_by_id),
        ("Event not found", test_event_not_found),
        ("Prometheus metrics", test_metrics),
        ("Invalid JSON", test_webhook_invalid_json),
        ("Isolations API", test_isolations_api),
    ]

    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn(server)
            passed += 1
        except Exception as e:
            print(f"  FAIL: {name} — {e}")
            failed += 1

    print()
    print("=" * 55)
    print(f" Results: {passed} passed, {failed} failed, {passed + failed} total")
    print("=" * 55)

    server.shutdown()
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_all())
