"""
Event processing pipeline.

FalcoEvent → Classify → Differential Response → Store → Metrics
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from models.events import FalcoEvent, Classification, ResponseRecord
from core.classifier import ThreatClassifier, _downgrade_severity
from core.false_positive_filter import FalsePositiveFilter
from core.heartbeat import HeartbeatMonitor, HEARTBEAT_RULE
from core.metrics import MetricsStore
from core import EventStore
from k8s.client import KubeClient

logger = logging.getLogger("processor")


class EventProcessor:
    """
    Orchestrates the full event processing pipeline:
    1. Parse Falco webhook payload → FalcoEvent
    2. Classify severity → Classification
    3. Execute differential response
    4. Record to event store
    5. Update Prometheus metrics
    """

    def __init__(self, classifier: ThreatClassifier, kube: KubeClient,
                 store: EventStore, metrics: MetricsStore,
                 auto_isolate: bool = True,
                 heartbeat_monitor: Optional[HeartbeatMonitor] = None,
                 fp_filter: Optional[FalsePositiveFilter] = None):
        self.classifier = classifier
        self.kube = kube
        self.store = store
        self.metrics = metrics
        self.auto_isolate = auto_isolate
        self.heartbeat_monitor = heartbeat_monitor
        self.fp_filter = fp_filter

    def process(self, raw_event: dict) -> Optional[ResponseRecord]:
        """Process a single Falco event. Thread-safe."""

        # --- Step 1: Parse ---
        event = FalcoEvent.from_webhook(raw_event)

        # --- Step 1.5: Heartbeat 타임스탬프 갱신 ---
        # 모든 이벤트 수신 시 last_event_time 갱신 (침묵 탐지용)
        if self.heartbeat_monitor:
            self.heartbeat_monitor.record_event(event.rule)

        # Heartbeat canary 이벤트는 보안 파이프라인을 통과시키지 않음
        if event.rule == HEARTBEAT_RULE:
            logger.debug("Heartbeat canary received — skipping security pipeline")
            return None

        # --- Step 1.6: Enrich K8s metadata ---
        # Host-mode Falco doesn't resolve K8s metadata, so we do it here
        # using container_id → Pod lookup via K8s API
        self._enrich_k8s_metadata(event)

        logger.info(
            "Event: rule=%s priority=%s ns=%s pod=%s",
            event.rule, event.priority, event.k8s.namespace, event.k8s.pod_name,
        )

        # --- Step 1.7: False Positive 2차 필터 ---
        fp_result = None
        if self.fp_filter:
            fp_result = self.fp_filter.check(event)

        # --- Step 2: Classify ---
        classification = self.classifier.classify(event)

        # --- Step 2.5: FP 필터 결과를 분류에 반영 ---
        if fp_result:
            classification.fp_score = fp_result.fp_score

            # 억제 대상이 아닌 이벤트 중 downgrade 대상 처리
            if fp_result.downgrade_severity and not fp_result.is_suppressed:
                old_sev = classification.severity
                classification.severity = _downgrade_severity(classification.severity)
                if classification.severity != old_sev:
                    classification.reason += (
                        f" | fp_downgrade({old_sev}→{classification.severity}"
                        f",fp_score={fp_result.fp_score:.3f})"
                    )

        logger.info(
            "Classified: severity=%s source=%s confidence=%.2f fp_score=%.3f reason=%s",
            classification.severity, classification.source,
            classification.confidence, classification.fp_score, classification.reason,
        )

        # --- Step 3: Build response record ---
        record = ResponseRecord(
            timestamp=event.time or datetime.now(timezone.utc).isoformat(),
            rule=event.rule,
            priority=event.priority,
            severity=classification.severity,
            classification_source=classification.source,
            classification_reason=classification.reason,
            confidence=classification.confidence,
            namespace=event.k8s.namespace,
            pod_name=event.k8s.pod_name,
            container_name=event.k8s.container_name,
            image=event.k8s.image,
            user=event.k8s.user,
            command=event.k8s.command,
        )

        # --- Step 3.5: FP 억제 마킹 ---
        if fp_result and fp_result.is_suppressed:
            record.suppressed = True
            record.suppression_reason = (
                f"fp_score={fp_result.fp_score:.3f} | {fp_result.reason}"
            )

        # --- Step 4: Differential response ---
        if record.suppressed:
            record.action_taken = "fp_suppressed"
            logger.info(
                "FP suppressed (action=fp_suppressed): rule=%s score=%.3f",
                event.rule, fp_result.fp_score,
            )
            self.metrics.inc_fp_suppressed(rule=event.rule)
        else:
            record.action_taken = self._execute_response(
                classification.severity, event, classification, record
            )
            if fp_result and fp_result.downgrade_severity:
                self.metrics.inc_fp_downgraded()

        # --- Step 5: Store ---
        event_id = self.store.add(record)
        logger.info(
            "Stored: id=%s action=%s severity=%s rule=%s",
            event_id, record.action_taken, record.severity, record.rule,
        )

        # --- Step 6: Metrics ---
        self.metrics.inc_event(
            classification.severity,
            rule=event.rule,
            namespace=event.k8s.namespace,
        )
        self.metrics.inc_action(record.action_taken)

        return record

    def _execute_response(self, severity: str, event: FalcoEvent,
                          classification: Classification,
                          record: ResponseRecord) -> str:
        """
        Execute differential response based on severity.
        Returns action string.
        """

        if severity == "low":
            logger.info(
                "LOW — log only: %s in %s/%s",
                event.rule, event.k8s.namespace, event.k8s.pod_name,
            )
            return "log_only"

        elif severity == "medium":
            logger.warning(
                "MEDIUM — alert: %s in %s/%s | %s",
                event.rule, event.k8s.namespace, event.k8s.pod_name,
                classification.reason,
            )
            # TODO: Slack/email notification (2차 개발)
            return "alert_and_monitor"

        elif severity == "high":
            return self._handle_high_severity(event, classification, record)

        else:
            logger.warning("Unknown severity: %s — treating as medium", severity)
            return "alert_and_monitor"

    def _handle_high_severity(self, event: FalcoEvent,
                               classification: Classification,
                               record: ResponseRecord) -> str:
        """Handle HIGH severity: auto-isolate with NetworkPolicy."""
        ns = event.k8s.namespace
        pod = event.k8s.pod_name

        logger.critical(
            "HIGH — isolating: %s in %s/%s | %s",
            event.rule, ns, pod, classification.reason,
        )

        if not self.auto_isolate:
            logger.info("Auto-isolate disabled, logging only")
            return "auto_isolate_disabled"

        if not ns or not pod:
            logger.warning("Missing namespace/pod info, cannot isolate")
            return "auto_isolate_no_target"

        # Get pod labels for precise NetworkPolicy targeting
        labels = self.kube.get_pod_labels(ns, pod)

        # Create deny-all NetworkPolicy
        policy_name = self.kube.create_isolation_policy(
            namespace=ns,
            pod_name=pod,
            labels=labels,
            reason=f"Rule: {event.rule} | {classification.reason}",
        )

        if policy_name:
            record.isolation_policy_name = policy_name
            self.metrics.inc_isolation()
            return "auto_isolate"
        else:
            self.metrics.inc_isolation(error=True)
            return "auto_isolate_failed"

    def _enrich_k8s_metadata(self, event: FalcoEvent):
        """
        If K8s namespace/pod are missing but container_id is present,
        resolve via K8s API. This handles host-mode Falco where K8s
        metadata enrichment doesn't work automatically.
        """
        # Skip if already has K8s info
        if event.k8s.namespace and event.k8s.pod_name:
            return

        container_id = event.k8s.container_id
        if not container_id or container_id == "host":
            return

        pod_info = self.kube.resolve_container_to_pod(container_id)
        if pod_info:
            event.k8s.namespace = pod_info.get("namespace", "")
            event.k8s.pod_name = pod_info.get("pod_name", "")
            event.k8s.container_name = pod_info.get("container_name", "") or event.k8s.container_name
            event.k8s.image = pod_info.get("image", "") or event.k8s.image
            logger.debug(
                "Enriched: container=%s → %s/%s",
                container_id[:12], event.k8s.namespace, event.k8s.pod_name,
            )
