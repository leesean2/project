"""
Threat classification module.

Two modes:
1. AI mode:      POST to AI module endpoint (이온 담당)
2. Fallback mode: Rule-based scoring using Falco priority + pattern analysis

Fallback is always available. AI is used when AI_ENDPOINT is configured.
On AI timeout/error, automatically falls back.
"""

import json
import logging
import time
import urllib.request
import urllib.error
from typing import Optional

from models.events import FalcoEvent, Classification

logger = logging.getLogger("classifier")


# ─── Falco Priority → Base Severity ──────────────────────
PRIORITY_TO_SEVERITY = {
    "Emergency": "high",
    "Alert":     "high",
    "Critical":  "high",
    "Error":     "medium",
    "Warning":   "medium",
    "Notice":    "low",
    "Informational": "low",
    "Debug":     "low",
}

# ─── Rule Pattern → Severity Boost ───────────────────────
# Keywords in rule name that should boost severity
RULE_BOOST_PATTERNS = {
    "high": [
        "privilege escalation",
        "reverse shell",
        "crypto mining",
        "container escape",
    ],
    "medium": [
        "shell spawned",
        "sensitive file",
        "write to monitored",
        "shadow",
        "passwd",
    ],
}

# ─── Context Scoring Factors ─────────────────────────────
# Additional signals from output_fields that affect severity
CONTEXT_WEIGHTS = {
    # Running as root is more dangerous
    "root_user": 1,
    # Production namespace is higher risk
    "prod_namespace": 1,
    # Multiple suspicious signals in same event
    "multi_signal": 1,
    # Known attacker tools
    "attacker_tool": 2,
}

ATTACKER_TOOLS = {
    "nmap", "ncat", "netcat", "msfconsole", "msfvenom",
    "metasploit", "hydra", "john", "hashcat", "mimikatz",
    "linpeas", "winpeas", "pspy",
}

# Processes that are normal container runtime activity — never suspicious
BENIGN_PROCESSES = {
    "runc", "containerd", "containerd-shim", "dockerd", "docker",
    "kubelet", "kube-proxy", "coredns", "etcd", "kube-apiserver",
    "kube-scheduler", "kube-controller", "pause", "tini",
    "falco", "falcoctl",
}

PROD_NAMESPACE_PATTERNS = {"prod", "production", "live", "stable"}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def _max_severity(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


def _downgrade_severity(s: str) -> str:
    """severity를 한 단계 낮춤: high→medium, medium→low, low→low."""
    if s == "high":
        return "medium"
    if s == "medium":
        return "low"
    return "low"


# AI confidence 임계값 기본값 — 이 아래이면 fallback으로 재분류
DEFAULT_AI_CONFIDENCE_THRESHOLD = 0.6
# Fallback confidence 임계값 — 이 아래이면 severity 한 단계 하향
DEFAULT_FALLBACK_CONFIDENCE_THRESHOLD = 0.35


class ThreatClassifier:
    """Classifies Falco events into low/medium/high severity."""

    def __init__(
        self,
        ai_endpoint: str = "",
        ai_timeout: int = 5,
        metrics=None,
        ai_confidence_threshold: float = DEFAULT_AI_CONFIDENCE_THRESHOLD,
        fallback_confidence_threshold: float = DEFAULT_FALLBACK_CONFIDENCE_THRESHOLD,
    ):
        self.ai_endpoint = ai_endpoint
        self.ai_timeout = ai_timeout
        self.metrics = metrics
        self.ai_confidence_threshold = ai_confidence_threshold
        self.fallback_confidence_threshold = fallback_confidence_threshold

    def classify(self, event: FalcoEvent) -> Classification:
        """
        Main classification entry point.
        1. AI 분류 시도 → confidence < threshold이면 fallback 사용
        2. Fallback 분류 → confidence < threshold이면 severity 하향
        """
        if self.ai_endpoint:
            result = self._classify_ai(event)
            if result is not None:
                if result.confidence >= self.ai_confidence_threshold:
                    return result
                # AI 확신도 부족 → fallback으로 재분류
                logger.warning(
                    "AI confidence too low (%.2f < %.2f) for rule=%s — falling back",
                    result.confidence, self.ai_confidence_threshold, event.rule,
                )
                if self.metrics:
                    self.metrics.inc_ai(error=False, fallback=True)
            else:
                logger.warning("AI unavailable, using fallback classification")

        return self._classify_fallback(event)

    # ─── AI Classification ────────────────────────────────

    def _classify_ai(self, event: FalcoEvent) -> Optional[Classification]:
        """Call external AI classification module."""
        payload = {
            "rule": event.rule,
            "priority": event.priority,
            "output": event.output,
            "output_fields": event.output_fields,
            "tags": event.tags,
            "time": event.time,
        }

        start = time.time()
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.ai_endpoint,
                data=data,
                method="POST",
                headers={"Content-Type": "application/json"},
            )

            if self.metrics:
                self.metrics.inc_ai()

            with urllib.request.urlopen(req, timeout=self.ai_timeout) as resp:
                duration = time.time() - start
                if self.metrics:
                    self.metrics.observe_ai_latency(duration)

                result = json.loads(resp.read().decode("utf-8"))
                severity = result.get("severity", "medium").lower()
                if severity not in SEVERITY_ORDER:
                    severity = "medium"

                logger.info(
                    "AI classification: severity=%s confidence=%.2f (%.3fs)",
                    severity, result.get("confidence", 0), duration,
                )

                return Classification(
                    severity=severity,
                    reason=result.get("reason", "AI classification"),
                    confidence=result.get("confidence", 0.0),
                    source="ai",
                )

        except Exception as e:
            duration = time.time() - start
            logger.warning("AI classification failed (%.3fs): %s", duration, e)
            if self.metrics:
                self.metrics.inc_ai(error=True, fallback=True)
                self.metrics.observe_ai_latency(duration)
            return None

    # ─── Fallback Rule-Based Classification ───────────────

    def _classify_fallback(self, event: FalcoEvent) -> Classification:
        """
        Multi-factor rule-based classification:
        1. Benign process check (early low)
        2. Base severity from Falco priority
        3. Rule name pattern matching
        4. Context scoring (user, namespace, tools)
        """
        reasons = []
        fields = event.output_fields

        # --- Factor 0: Benign process early-out ---
        proc_name = fields.get("proc.name") or ""
        cmdline = fields.get("proc.cmdline") or ""
        if proc_name in BENIGN_PROCESSES or cmdline.startswith("runc:"):
            return Classification(
                severity="low",
                reason=f"benign_process:{proc_name or cmdline[:30]}",
                confidence=0.9,
                source="fallback",
            )

        # --- Factor 1: Base severity from priority ---
        base = PRIORITY_TO_SEVERITY.get(event.priority, "medium")
        reasons.append(f"priority={event.priority}->base:{base}")

        severity = base

        # --- Factor 2: Rule name pattern boost ---
        rule_lower = event.rule.lower()
        for target_sev, patterns in RULE_BOOST_PATTERNS.items():
            for pattern in patterns:
                if pattern in rule_lower:
                    severity = _max_severity(severity, target_sev)
                    reasons.append(f"rule_pattern:{pattern}->{target_sev}")
                    break

        # --- Factor 3: Context scoring ---
        score = 0

        # Root user?
        user_uid = fields.get("user.uid")
        user_name = fields.get("user.name") or ""
        if user_uid == 0 or user_name == "root":
            score += CONTEXT_WEIGHTS["root_user"]
            reasons.append("ctx:root_user")

        # Production namespace?
        ns = event.k8s.namespace.lower() if event.k8s.namespace else ""
        if any(p in ns for p in PROD_NAMESPACE_PATTERNS):
            score += CONTEXT_WEIGHTS["prod_namespace"]
            reasons.append(f"ctx:prod_ns({event.k8s.namespace})")

        # Attacker tools? (exact proc.name match only — no substring)
        if proc_name in ATTACKER_TOOLS:
            score += CONTEXT_WEIGHTS["attacker_tool"]
            reasons.append(f"ctx:attacker_tool({proc_name})")

        # Multiple tags suggesting compound threat?
        threat_tags = {"privilege-escalation", "exfiltration", "shell", "file-access"}
        matching_tags = threat_tags.intersection(set(event.tags))
        if len(matching_tags) >= 2:
            score += CONTEXT_WEIGHTS["multi_signal"]
            reasons.append(f"ctx:multi_signal({','.join(matching_tags)})")

        # Apply context score
        if score >= 3:
            severity = _max_severity(severity, "high")
            reasons.append(f"ctx_score:{score}->high")
        elif score >= 1:
            severity = _max_severity(severity, "medium")
            reasons.append(f"ctx_score:{score}->medium")

        reason_str = " | ".join(reasons)
        # Confidence is higher when more factors agree
        confidence = min(0.3 + (score * 0.15) + (0.2 if severity == base else 0), 0.95)
        confidence = round(confidence, 2)

        # Fallback confidence 임계값 미달 시 severity 한 단계 하향
        if confidence < self.fallback_confidence_threshold:
            old_sev = severity
            severity = _downgrade_severity(severity)
            if severity != old_sev:
                reasons.append(
                    f"low_conf_downgrade({old_sev}->{severity},conf={confidence:.2f})"
                )
                reason_str = " | ".join(reasons)

        return Classification(
            severity=severity,
            reason=reason_str,
            confidence=confidence,
            source="fallback",
        )
