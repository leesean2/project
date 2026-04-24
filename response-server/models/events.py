"""
Data models for the runtime detection pipeline.

FalcoEvent → Classification → ResponseRecord
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

# ─── 입력값 길이 상한 ─────────────────────────────────────
# [HIGH #3] 비정상적으로 긴 필드로 메모리/로그 오염 방지
_MAX_FIELD_LEN = 512    # 일반 문자열 필드
_MAX_OUTPUT_LEN = 2048  # output / cmdline
_MAX_TAG_COUNT  = 32    # 태그 최대 개수
_MAX_TAG_LEN    = 64    # 태그 하나의 최대 길이


def _truncate(value, max_len: int = _MAX_FIELD_LEN) -> str:
    """문자열로 변환 후 max_len 초과 시 잘라냄."""
    if not isinstance(value, str):
        value = str(value) if value is not None else ""
    return value[:max_len]


def _safe_tags(raw_tags) -> list:
    """
    [HIGH #3] 태그 목록 검증.
    - 리스트가 아니면 빈 리스트 반환
    - 최대 _MAX_TAG_COUNT개, 각 항목은 문자열로 변환 후 _MAX_TAG_LEN 자로 제한
    """
    if not isinstance(raw_tags, list):
        return []
    return [
        _truncate(t, _MAX_TAG_LEN)
        for t in raw_tags[:_MAX_TAG_COUNT]
    ]


def _safe_output_fields(raw_fields) -> dict:
    """
    [HIGH #3] output_fields 딕셔너리 검증.
    - 딕셔너리가 아니면 빈 딕셔너리 반환
    - 각 키/값을 문자열로 변환 후 길이 제한
    """
    if not isinstance(raw_fields, dict):
        return {}
    result = {}
    for k, v in list(raw_fields.items())[:64]:   # 최대 64개 필드
        safe_k = _truncate(k, 128)
        # 숫자 등 기본형은 그대로 유지, 문자열만 길이 제한
        if isinstance(v, str):
            safe_v = _truncate(v, _MAX_FIELD_LEN)
        elif isinstance(v, (int, float, bool)):
            safe_v = v
        else:
            safe_v = _truncate(str(v), _MAX_FIELD_LEN)
        result[safe_k] = safe_v
    return result


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
        # [HIGH #3] 각 필드를 _truncate로 길이 제한
        return cls(
            namespace=_truncate(fields.get("k8s.ns.name", "")),
            pod_name=_truncate(fields.get("k8s.pod.name", "")),
            container_id=_truncate(fields.get("container.id", ""), 128),
            container_name=_truncate(fields.get("container.name", "")),
            image=_truncate(fields.get("container.image.repository", "")),
            user=_truncate(fields.get("user.name", "")),
            command=_truncate(fields.get("proc.cmdline", ""), _MAX_OUTPUT_LEN),
            pid=_truncate(str(fields.get("proc.pid", "")), 16),
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
        """
        [HIGH #3] 모든 필드에 타입 검증 + 길이 제한 적용.
        - raw가 dict가 아니면 빈 이벤트 반환
        - 각 문자열 필드는 _truncate로 상한 적용
        - output_fields / tags는 별도 검증 함수 통과
        """
        if not isinstance(raw, dict):
            return cls()

        event = cls(
            rule=_truncate(raw.get("rule", "")),
            priority=_truncate(raw.get("priority", ""), 32),
            output=_truncate(raw.get("output", ""), _MAX_OUTPUT_LEN),
            output_fields=_safe_output_fields(raw.get("output_fields", {})),
            tags=_safe_tags(raw.get("tags", [])),
            time=_truncate(raw.get("time", datetime.now(timezone.utc).isoformat()), 64),
            source=_truncate(raw.get("source", "syscall"), 32),
            hostname=_truncate(raw.get("hostname", "")),
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
