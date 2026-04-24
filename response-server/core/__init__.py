"""
In-memory event store with ring buffer.

Stores the last N response records for:
- Dashboard API (이온 연동)
- Audit trail
- Pattern analysis (AI 위반 패턴 분석 용)
"""

import threading
import time
import uuid
from collections import deque
from typing import List, Optional

from models.events import ResponseRecord


class EventStore:
    """Thread-safe ring buffer for processed events."""

    def __init__(self, max_size: int = 1000):
        self._lock = threading.Lock()
        self._events: deque = deque(maxlen=max_size)

    def add(self, record: ResponseRecord) -> str:
        """Add a record and return its assigned ID."""
        with self._lock:
            # [열거 공격 방지] 순차 ID 대신 UUID — 예측 불가 식별자 사용
            record.id = f"evt-{uuid.uuid4().hex}"
            self._events.append(record)
            return record.id

    def get_all(self) -> List[dict]:
        """Return all stored events (newest first)."""
        with self._lock:
            return [r.to_dict() for r in reversed(self._events)]

    def get_recent(self, count: int = 50) -> List[dict]:
        """Return the N most recent events."""
        with self._lock:
            items = list(self._events)[-count:]
            return [r.to_dict() for r in reversed(items)]

    def get_by_severity(self, severity: str) -> List[dict]:
        """Filter events by severity level."""
        with self._lock:
            return [
                r.to_dict() for r in reversed(self._events)
                if r.severity == severity
            ]

    def get_by_namespace(self, namespace: str) -> List[dict]:
        """Filter events by Kubernetes namespace."""
        with self._lock:
            return [
                r.to_dict() for r in reversed(self._events)
                if r.namespace == namespace
            ]

    def get_by_id(self, event_id: str) -> Optional[dict]:
        """Get a single event by ID."""
        with self._lock:
            for r in self._events:
                if r.id == event_id:
                    return r.to_dict()
            return None

    def get_summary(self) -> dict:
        """
        Aggregated summary for dashboard.
        Returns counts by severity, by rule, by namespace, by action.
        """
        with self._lock:
            summary = {
                "total_events": len(self._events),
                "by_severity": {},
                "by_rule": {},
                "by_namespace": {},
                "by_action": {},
                "recent_high": [],
            }

            for r in self._events:
                # By severity
                summary["by_severity"][r.severity] = \
                    summary["by_severity"].get(r.severity, 0) + 1

                # By rule
                summary["by_rule"][r.rule] = \
                    summary["by_rule"].get(r.rule, 0) + 1

                # By namespace
                if r.namespace:
                    summary["by_namespace"][r.namespace] = \
                        summary["by_namespace"].get(r.namespace, 0) + 1

                # By action
                summary["by_action"][r.action_taken] = \
                    summary["by_action"].get(r.action_taken, 0) + 1

            # Last 10 high-severity events — timestamp 기준 최신순 정렬 보장
            # [LOW #10] deque 순서는 삽입 순서이므로 타임스탬프 역전이 없다면
            # 문제없지만, 명시적으로 정렬하여 대시보드 표시 순서를 보장.
            high_events = [r for r in self._events if r.severity == "high"]
            high_events.sort(key=lambda r: r.timestamp, reverse=True)
            summary["recent_high"] = [
                r.to_dict() for r in high_events[:10]
            ]

            return summary

    def count(self) -> int:
        with self._lock:
            return len(self._events)

    def clear(self) -> int:
        """Clear all events. Returns count of cleared events."""
        with self._lock:
            count = len(self._events)
            self._events.clear()
            return count
