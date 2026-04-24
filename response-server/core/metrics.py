"""
Prometheus metrics exporter.

Exposes metrics for:
- Falco event counts (by severity, rule, namespace)
- NetworkPolicy isolation actions
- AI classification stats (latency, fallback rate)
- Response action distribution
"""

import threading
import time


class MetricsStore:
    """Thread-safe Prometheus-format metrics store."""

    def __init__(self):
        self._lock = threading.Lock()

        # Counters
        self.events_total = {}            # {severity: count}
        self.events_by_rule = {}          # {rule: count}
        self.events_by_namespace = {}     # {namespace: count}
        self.actions_total = {}           # {action: count}
        self.isolations_total = 0
        self.isolation_errors = 0
        self.ai_requests_total = 0
        self.ai_errors_total = 0
        self.ai_fallbacks_total = 0

        # Gauges
        self._start_time = time.time()

        # Falco health / heartbeat metrics
        self.falco_silence_total = 0        # 침묵 감지 누적 횟수
        self.falco_is_silenced = 0          # 현재 침묵 상태 (0=정상, 1=침묵)
        self.falco_last_event_age = 0.0     # 마지막 이벤트로부터 경과 시간(초)

        # Webhook 보안 거부 카운터 {reason_code: count}
        # 401=HMAC실패, 403=IP차단, 429=속도초과
        self.webhook_rejected = {}          # {status_code: count}

        # FP(오탐) 완화 카운터
        self.fp_suppressed_by_rule = {}     # {rule: count}
        self.fp_downgraded_total = 0        # severity 하향 이벤트 수

        # Histogram buckets for AI latency (seconds)
        self.ai_latency_buckets = [0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        self.ai_latency_counts = {b: 0 for b in self.ai_latency_buckets}
        self.ai_latency_count = 0
        self.ai_latency_sum = 0.0

    def inc_event(self, severity: str, rule: str = "", namespace: str = ""):
        with self._lock:
            self.events_total[severity] = self.events_total.get(severity, 0) + 1
            if rule:
                self.events_by_rule[rule] = self.events_by_rule.get(rule, 0) + 1
            if namespace:
                self.events_by_namespace[namespace] = \
                    self.events_by_namespace.get(namespace, 0) + 1

    def inc_action(self, action: str):
        with self._lock:
            self.actions_total[action] = self.actions_total.get(action, 0) + 1

    def inc_isolation(self, error: bool = False):
        with self._lock:
            if error:
                self.isolation_errors += 1
            else:
                self.isolations_total += 1

    def inc_webhook_rejected(self, status_code: int):
        with self._lock:
            key = str(status_code)
            self.webhook_rejected[key] = self.webhook_rejected.get(key, 0) + 1

    def inc_falco_silence(self):
        with self._lock:
            self.falco_silence_total += 1

    def set_falco_silenced(self, silenced: bool):
        with self._lock:
            self.falco_is_silenced = 1 if silenced else 0

    def set_falco_last_event_age(self, age_seconds: float):
        with self._lock:
            self.falco_last_event_age = age_seconds

    def inc_fp_suppressed(self, rule: str = ""):
        with self._lock:
            key = rule or "unknown"
            self.fp_suppressed_by_rule[key] = self.fp_suppressed_by_rule.get(key, 0) + 1

    def inc_fp_downgraded(self):
        with self._lock:
            self.fp_downgraded_total += 1

    def inc_ai(self, error: bool = False, fallback: bool = False):
        with self._lock:
            self.ai_requests_total += 1
            if error:
                self.ai_errors_total += 1
            if fallback:
                self.ai_fallbacks_total += 1

    def observe_ai_latency(self, duration_seconds: float):
        with self._lock:
            self.ai_latency_count += 1
            self.ai_latency_sum += duration_seconds
            for bucket in self.ai_latency_buckets:
                if duration_seconds <= bucket:
                    self.ai_latency_counts[bucket] += 1

    def render(self) -> str:
        """Render all metrics in Prometheus text exposition format."""
        with self._lock:
            lines = []

            # --- Events by severity ---
            lines.append("# HELP compliance_falco_events_total Total Falco events by severity")
            lines.append("# TYPE compliance_falco_events_total counter")
            for sev in ("low", "medium", "high"):
                count = self.events_total.get(sev, 0)
                lines.append(f'compliance_falco_events_total{{severity="{sev}"}} {count}')

            # --- Events by rule ---
            lines.append("# HELP compliance_falco_events_by_rule_total Events by Falco rule")
            lines.append("# TYPE compliance_falco_events_by_rule_total counter")
            for rule, count in self.events_by_rule.items():
                safe = rule.replace('"', '\\"')
                lines.append(f'compliance_falco_events_by_rule_total{{rule="{safe}"}} {count}')

            # --- Events by namespace ---
            lines.append("# HELP compliance_falco_events_by_namespace_total Events by namespace")
            lines.append("# TYPE compliance_falco_events_by_namespace_total counter")
            for ns, count in self.events_by_namespace.items():
                lines.append(f'compliance_falco_events_by_namespace_total{{namespace="{ns}"}} {count}')

            # --- Actions ---
            lines.append("# HELP compliance_response_actions_total Response actions taken")
            lines.append("# TYPE compliance_response_actions_total counter")
            for action, count in self.actions_total.items():
                safe = action.replace('"', '\\"')
                lines.append(f'compliance_response_actions_total{{action="{safe}"}} {count}')

            # --- Isolation ---
            lines.append("# HELP compliance_network_isolations_total Successful auto-isolation actions")
            lines.append("# TYPE compliance_network_isolations_total counter")
            lines.append(f"compliance_network_isolations_total {self.isolations_total}")
            lines.append("# HELP compliance_network_isolation_errors_total Failed isolation attempts")
            lines.append("# TYPE compliance_network_isolation_errors_total counter")
            lines.append(f"compliance_network_isolation_errors_total {self.isolation_errors}")

            # --- AI classification ---
            lines.append("# HELP compliance_ai_requests_total AI classification requests")
            lines.append("# TYPE compliance_ai_requests_total counter")
            lines.append(f"compliance_ai_requests_total {self.ai_requests_total}")
            lines.append("# HELP compliance_ai_errors_total AI classification errors")
            lines.append("# TYPE compliance_ai_errors_total counter")
            lines.append(f"compliance_ai_errors_total {self.ai_errors_total}")
            lines.append("# HELP compliance_ai_fallbacks_total Fallback to rule-based classification")
            lines.append("# TYPE compliance_ai_fallbacks_total counter")
            lines.append(f"compliance_ai_fallbacks_total {self.ai_fallbacks_total}")

            # --- AI latency histogram ---
            lines.append("# HELP compliance_ai_latency_seconds AI classification latency")
            lines.append("# TYPE compliance_ai_latency_seconds histogram")
            cumulative = 0
            for bucket in self.ai_latency_buckets:
                cumulative += self.ai_latency_counts[bucket]
                lines.append(
                    f'compliance_ai_latency_seconds_bucket{{le="{bucket}"}} {cumulative}'
                )
            lines.append(
                f'compliance_ai_latency_seconds_bucket{{le="+Inf"}} {self.ai_latency_count}'
            )
            lines.append(f"compliance_ai_latency_seconds_sum {self.ai_latency_sum:.6f}")
            lines.append(f"compliance_ai_latency_seconds_count {self.ai_latency_count}")

            # --- Webhook 보안 거부 통계 ---
            lines.append("# HELP compliance_webhook_rejected_total Webhook requests rejected by security middleware")
            lines.append("# TYPE compliance_webhook_rejected_total counter")
            for code, count in self.webhook_rejected.items():
                reason = {"401": "hmac_failed", "403": "ip_blocked", "429": "rate_limited"}.get(code, "other")
                lines.append(
                    f'compliance_webhook_rejected_total{{status="{code}",reason="{reason}"}} {count}'
                )

            # --- FP 오탐 완화 통계 ---
            lines.append("# HELP compliance_fp_suppressed_total Events suppressed as false positives by rule")
            lines.append("# TYPE compliance_fp_suppressed_total counter")
            for rule, count in self.fp_suppressed_by_rule.items():
                safe = rule.replace('"', '\\"')
                lines.append(f'compliance_fp_suppressed_total{{rule="{safe}"}} {count}')

            lines.append("# HELP compliance_fp_downgraded_total Events with severity downgraded by FP filter")
            lines.append("# TYPE compliance_fp_downgraded_total counter")
            lines.append(f"compliance_fp_downgraded_total {self.fp_downgraded_total}")

            # --- Falco health / heartbeat ---
            lines.append("# HELP compliance_falco_silence_total Times Falco event stream went silent")
            lines.append("# TYPE compliance_falco_silence_total counter")
            lines.append(f"compliance_falco_silence_total {self.falco_silence_total}")

            lines.append("# HELP compliance_falco_is_silenced 1 if Falco currently silent, 0 if healthy")
            lines.append("# TYPE compliance_falco_is_silenced gauge")
            lines.append(f"compliance_falco_is_silenced {self.falco_is_silenced}")

            lines.append("# HELP compliance_falco_last_event_age_seconds Seconds since last Falco event")
            lines.append("# TYPE compliance_falco_last_event_age_seconds gauge")
            lines.append(
                f"compliance_falco_last_event_age_seconds {self.falco_last_event_age:.1f}"
            )

            # --- Uptime ---
            lines.append("# HELP compliance_server_uptime_seconds Server uptime")
            lines.append("# TYPE compliance_server_uptime_seconds gauge")
            lines.append(
                f"compliance_server_uptime_seconds {time.time() - self._start_time:.1f}"
            )

            return "\n".join(lines) + "\n"
