"""
Policy-as-Code Compliance Platform — Runtime Response Server

Entry point. Wires up all modules and starts the HTTP server.

Modules:
  models/events.py    — FalcoEvent, Classification, ResponseRecord
  core/__init__.py    — EventStore (in-memory ring buffer)
  core/metrics.py     — MetricsStore (Prometheus exposition)
  core/classifier.py  — ThreatClassifier (AI + fallback)
  core/processor.py   — EventProcessor (pipeline orchestration)
  k8s/client.py       — KubeClient (NetworkPolicy CRUD)
  handlers/http.py    — RequestHandler (webhook + REST API)
"""

import logging
import os
import sys
import signal
from http.server import HTTPServer

# --- Configuration ---
CONFIG = {
    "port": int(os.getenv("SERVER_PORT", "5000")),
    "ai_endpoint": os.getenv("AI_ENDPOINT", ""),
    "ai_timeout": int(os.getenv("AI_TIMEOUT", "5")),
    "auto_isolate": os.getenv("AUTO_ISOLATE", "true").lower() == "true",
    "log_level": os.getenv("LOG_LEVEL", "INFO"),
    "event_store_size": int(os.getenv("EVENT_STORE_SIZE", "2000")),
    # ── False Positive 완화 임계값 ─────────────────────────
    # fp_score >= suppress_threshold → action = fp_suppressed (log_only 강제)
    "fp_suppress_threshold": float(os.getenv("FP_SUPPRESS_THRESHOLD", "0.75")),
    # fp_score >= downgrade_threshold → severity 한 단계 하향
    "fp_downgrade_threshold": float(os.getenv("FP_DOWNGRADE_THRESHOLD", "0.45")),
    # AI confidence < threshold → fallback 분류기 사용
    "ai_confidence_threshold": float(os.getenv("AI_CONFIDENCE_THRESHOLD", "0.6")),
    # Fallback confidence < threshold → severity 하향
    "fallback_confidence_threshold": float(os.getenv("FALLBACK_CONFIDENCE_THRESHOLD", "0.35")),
    # Falco 침묵 탐지: N초 동안 이벤트 없으면 CRITICAL 경보
    "heartbeat_silence_threshold": int(os.getenv("HEARTBEAT_SILENCE_THRESHOLD", "90")),
    # 침묵 감지 체크 주기 (초)
    "heartbeat_check_interval": int(os.getenv("HEARTBEAT_CHECK_INTERVAL", "30")),
    # ── Webhook 보안 ──────────────────────────────────────
    # HMAC-SHA256 공유 비밀키 (signing proxy와 동일한 값 필요)
    "webhook_secret": os.getenv("WEBHOOK_SECRET", ""),
    # True이면 서명 없는 요청 거부 (08-setup-signing-proxy.sh 실행 후 활성화)
    "webhook_hmac_required": os.getenv("WEBHOOK_HMAC_REQUIRED", "true").lower() == "true",
    # 허용 소스 IP 목록 (콤마 구분, CIDR 지원). 빈 문자열이면 비활성화.
    "webhook_ip_whitelist": [
        ip.strip()
        for ip in os.getenv("WEBHOOK_IP_WHITELIST", "").split(",")
        if ip.strip()
    ],
    # IP당 burst 허용 요청 수
    "rate_limit_capacity": int(os.getenv("RATE_LIMIT_CAPACITY", "100")),
    # IP당 초당 토큰 충전 속도 (지속 RPS)
    "rate_limit_refill_rate": float(os.getenv("RATE_LIMIT_REFILL_RATE", "3.0")),
}

# --- Logging ---
logging.basicConfig(
    level=getattr(logging, CONFIG["log_level"]),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
    stream=sys.stdout,
)
logger = logging.getLogger("main")


# --- Custom HTTPServer to inject dependencies ---
class AppServer(HTTPServer):
    """HTTPServer with application dependencies attached."""

    def __init__(self, address, handler, processor, store, metrics, kube, heartbeat, security):
        super().__init__(address, handler)
        self.processor = processor
        self.store = store
        self.metrics = metrics
        self.kube = kube
        self.heartbeat = heartbeat
        self.security = security


def _validate_config(config: dict) -> None:
    """시작 전 보안 필수 설정 검증. 치명적 오류 시 즉시 종료."""
    if config["webhook_hmac_required"] and not config["webhook_secret"]:
        logger.critical(
            "WEBHOOK_SECRET이 설정되지 않은 상태에서 WEBHOOK_HMAC_REQUIRED=true입니다. "
            "서버를 시작할 수 없습니다. "
            "08-setup-signing-proxy.sh를 실행하거나 WEBHOOK_SECRET 환경변수를 설정하세요."
        )
        sys.exit(1)


def main():
    """Initialize all modules and start servers."""
    
    _validate_config(CONFIG)

    # --- Import modules ---
    from core import EventStore
    from core.metrics import MetricsStore
    from core.classifier import ThreatClassifier
    from core.false_positive_filter import FalsePositiveFilter
    from core.heartbeat import HeartbeatMonitor
    from core.processor import EventProcessor
    from k8s.client import KubeClient
    from handlers.http import RequestHandler
    from middleware.security import WebhookSecurity

    # --- Initialize components ---
    metrics = MetricsStore()
    store = EventStore(max_size=CONFIG["event_store_size"])
    kube = KubeClient()
    classifier = ThreatClassifier(
        ai_endpoint=CONFIG["ai_endpoint"],
        ai_timeout=CONFIG["ai_timeout"],
        metrics=metrics,
        ai_confidence_threshold=CONFIG["ai_confidence_threshold"],
        fallback_confidence_threshold=CONFIG["fallback_confidence_threshold"],
    )
    fp_filter = FalsePositiveFilter(
        suppress_threshold=CONFIG["fp_suppress_threshold"],
        downgrade_threshold=CONFIG["fp_downgrade_threshold"],
    )
    heartbeat = HeartbeatMonitor(
        metrics=metrics,
        silence_threshold=CONFIG["heartbeat_silence_threshold"],
        check_interval=CONFIG["heartbeat_check_interval"],
    )
    security = WebhookSecurity(
        secret=CONFIG["webhook_secret"],
        hmac_required=CONFIG["webhook_hmac_required"],
        ip_whitelist=CONFIG["webhook_ip_whitelist"] or None,
        rate_limit_capacity=CONFIG["rate_limit_capacity"],
        rate_limit_refill_rate=CONFIG["rate_limit_refill_rate"],
    )
    processor = EventProcessor(
        classifier=classifier,
        kube=kube,
        store=store,
        metrics=metrics,
        auto_isolate=CONFIG["auto_isolate"],
        heartbeat_monitor=heartbeat,
        fp_filter=fp_filter,
    )

    # --- Print startup banner ---
    logger.info("=" * 60)
    logger.info("Compliance Runtime Response Server")
    logger.info("=" * 60)
    logger.info("  Webhook:      0.0.0.0:%d/webhook", CONFIG["port"])
    logger.info("  Metrics:      0.0.0.0:%d/metrics", CONFIG["port"])
    logger.info("  Events API:   0.0.0.0:%d/api/v1/events", CONFIG["port"])
    logger.info("  Isolations:   0.0.0.0:%d/api/v1/isolations", CONFIG["port"])
    logger.info("  AI endpoint:  %s", CONFIG["ai_endpoint"] or "(fallback mode)")
    logger.info("  Auto-isolate: %s", CONFIG["auto_isolate"])
    logger.info(
        "  FP filter:    suppress>=%.2f  downgrade>=%.2f",
        CONFIG["fp_suppress_threshold"],
        CONFIG["fp_downgrade_threshold"],
    )
    logger.info(
        "  Confidence:   ai_threshold=%.2f  fallback_threshold=%.2f",
        CONFIG["ai_confidence_threshold"],
        CONFIG["fallback_confidence_threshold"],
    )
    logger.info("  Store size:   %d events", CONFIG["event_store_size"])
    logger.info("  In-cluster:   %s", kube.is_in_cluster())
    logger.info(
        "  Heartbeat:    silence_threshold=%ds check_interval=%ds",
        CONFIG["heartbeat_silence_threshold"],
        CONFIG["heartbeat_check_interval"],
    )
    logger.info(
        "  HMAC:         enabled=%s required=%s",
        bool(CONFIG["webhook_secret"]),
        CONFIG["webhook_hmac_required"],
    )
    logger.info(
        "  IP whitelist: %s",
        ", ".join(CONFIG["webhook_ip_whitelist"]) or "(disabled)",
    )
    logger.info(
        "  Rate limit:   burst=%d refill=%.1f/s",
        CONFIG["rate_limit_capacity"],
        CONFIG["rate_limit_refill_rate"],
    )
    logger.info("=" * 60)

    # --- Start heartbeat monitor ---
    heartbeat.start()

    # --- Start server ---
    server = AppServer(
        ("0.0.0.0", CONFIG["port"]),
        RequestHandler,
        processor=processor,
        store=store,
        metrics=metrics,
        kube=kube,
        heartbeat=heartbeat,
        security=security,
    )

    # Graceful shutdown
    def shutdown_handler(signum, frame):
        logger.info("Received signal %d, shutting down...", signum)
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    logger.info("Server listening on :%d", CONFIG["port"])

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Interrupted, shutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
