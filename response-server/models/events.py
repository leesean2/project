"""
Data models for the runtime detection pipeline.

FalcoEvent → Classification → ResponseRecord
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class K8sContext:
    """Kubernetes metadata extracted from Falco output_fields."""
    namespace: str = ""
    pod_name: str = ""
    container_id: str = ""
    container_name: str = ""
    image: str = ""
    user: str = ""
    command: str = ""
    pid: str = ""

    @classmethod
    def from_output_fields(cls, fields: dict) -> "K8sContext":
        return cls(
            namespace=fields.get("k8s.ns.name", ""),
            pod_name=fields.get("k8s.pod.name", ""),
            container_id=fields.get("container.id", ""),
            container_name=fields.get("container.name", ""),
            image=fields.get("container.image.repository", ""),
            user=fields.get("user.name", ""),
            command=fields.get("proc.cmdline", ""),
            pid=str(fields.get("proc.pid", "")),
        )


@dataclass
class FalcoEvent:
    """Parsed Falco alert from Sidekick webhook."""
    rule: str = ""
    priority: str = ""
    output: str = ""
    output_fields: dict = field(default_factory=dict)
    tags: list = field(default_factory=list)
    time: str = ""
    source: str = "syscall"
    hostname: str = ""

    # Derived
    k8s: K8sContext = field(default_factory=K8sContext)

    @classmethod
    def from_webhook(cls, raw: dict) -> "FalcoEvent":
        event = cls(
            rule=raw.get("rule", ""),
            priority=raw.get("priority", ""),
            output=raw.get("output", ""),
            output_fields=raw.get("output_fields", {}),
            tags=raw.get("tags", []),
            time=raw.get("time", datetime.now(timezone.utc).isoformat()),
            source=raw.get("source", "syscall"),
            hostname=raw.get("hostname", ""),
        )
        event.k8s = K8sContext.from_output_fields(event.output_fields)
        return event

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Classification:
    """AI or fallback threat classification result."""
    severity: str = "medium"  # low / medium / high
    reason: str = ""
    confidence: float = 0.0   # 0.0 ~ 1.0
    source: str = "fallback"  # ai / fallback
    fp_score: float = 0.0     # FalsePositiveFilter가 산정한 오탐 점수 (0~1)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ResponseRecord:
    """Complete record of event processing — stored for audit trail."""
    id: str = ""
    timestamp: str = ""
    rule: str = ""
    priority: str = ""
    severity: str = ""
    classification_source: str = ""
    classification_reason: str = ""
    confidence: float = 0.0
    namespace: str = ""
    pod_name: str = ""
    container_name: str = ""
    image: str = ""
    user: str = ""
    command: str = ""
    action_taken: str = ""  # log_only / alert_and_monitor / auto_isolate / fp_suppressed / ...
    isolation_policy_name: str = ""  # NetworkPolicy name if created
    suppressed: bool = False          # FP 필터에 의해 억제됨
    suppression_reason: str = ""      # 억제 사유 (fp_score 포함)

    def to_dict(self) -> dict:
        return asdict(self)
