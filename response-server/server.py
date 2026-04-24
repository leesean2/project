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
    # [HIGH #1] 바인딩 주소를 환경변수로 분리.
    # 프로덕션: "127.0.0.1" (ClusterIP 서비스가 앞단에서 받으므로 루프백으로 충분)
    # 클러스터 내 Pod 간 통신이 필요한 경우만 "0.0.0.0" 으로 설정.
    "bind_host": os.getenv("SERVER_BIND_HOST", "0.0.0.0"),
    "ai_endpoint": os.getenv("AI_ENDPOINT", ""),
    "ai_timeout": int(os.getenv("AI_TIMEOUT", "5")),
    "auto_isolate": os.getenv("AUTO_ISOLATE", "true").lower() == "true",
    "log_level": os.getenv("LOG_LEVEL", "INFO"),
    "event_store_size": int(os.getenv("EVENT_STORE_SIZE", "2000")),
    # ── False Positive 완화 임계값 ─────────────────────────
    "fp_suppress_threshold": float(os.getenv("FP_SUPPRESS_THRESHOLD", "0.75")),
    "fp_downgrade_threshold": float(os.getenv("FP_DOWNGRADE_THRESHOLD", "0.45")),
    "ai_confidence_threshold": float(os.getenv("AI_CONFIDENCE_THRESHOLD", "0.6")),
    "fallback_confidence_threshold": float(os.getenv("FALLBACK_CONFIDENCE_THRESHOLD", "0.35")),
    # ── Heartbeat ─────────────────────────────────────────
    "heartbeat_silence_threshold": int(os.getenv("HEARTBEAT_SILENCE_THRESHOLD", "90")),
    "heartbeat_check_interval": int(os.getenv("HEARTBEAT_CHECK_INTERVAL", "30")),
    # ── Webhook 보안 ──────────────────────────────────────
    "webhook_secret": os.getenv("WEBHOOK_SECRET", ""),
    "webhook_hmac_required": os.getenv("WEBHOOK_HMAC_REQUIRED", "true").lower() == "true",
    "webhook_ip_whitelist": [
        ip.strip()
        for ip in os.getenv("WEBHOOK_IP_WHITELIST", "").split(",")
        if ip.strip()
    ],
    "rate_limit_capacity": int(os.getenv("RATE_LIMIT_CAPACITY", "100")),
    "rate_limit_refill_rate": float(os.getenv("RATE_LIMIT_REFILL_RATE", "3.0")),
    # ── REST API / Heartbeat 인증 ─────────────────────────
    "api_token": os.getenv("API_TOKEN", ""),
    "heartbeat_token": os.getenv("HEARTBEAT_TOKEN", ""),
    # ── CORS ─────────────────────────────────────────────
    "allowed_origins": os.getenv("ALLOWED_ORIGINS", "http://localhost:3000"),
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
    """
    시작 전 보안 필수 설정 검증. 치명적 오류 시 즉시 종료.

    [HIGH #2] security 모듈 임포트 전에 설정값을 검증하여
    잘못된 설정으로 security=None 상태로 서버가 시작되는 것을 방지.
    """
    # HMAC 설정 검증
    if config["webhook_hmac_required"] and not config["webhook_secret"]:
        logger.critical(
            "WEBHOOK_SECRET이 설정되지 않은 상태에서 WEBHOOK_HMAC_REQUIRED=true입니다. "
            "서버를 시작할 수 없습니다. "
            "WEBHOOK_SECRET 환경변수를 설정하세요."
        )
        sys.exit(1)

    # [HIGH #2] API_TOKEN / HEARTBEAT_TOKEN 빈값 경고
    # 빈값이면 http.py에서 503을 반환하지만, 시작 시점에도 명시적으로 경고
    if not config["api_token"]:
        logger.warning(
            "API_TOKEN이 설정되지 않았습니다. "
            "DELETE /api/v1/isolations 및 인증 API가 503을 반환합니다. "
            "API_TOKEN 환경변수를 설정하세요."
        )
    if not config["heartbeat_token"]:
        logger.warning(
            "HEARTBEAT_TOKEN이 설정되지 않았습니다. "
            "POST /api/v1/heartbeat 가 503을 반환합니다. "
            "HEARTBEAT_TOKEN 환경변수를 설정하세요."
        )


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

    # [HIGH #2] security 모듈 임포트 실패 시 서버 시작 거부
    try:
        from middleware.security import WebhookSecurity
    except ImportError as e:
        logger.critical(
            "보안 미들웨어(middleware.security) 임포트 실패: %s. "
            "security=None 상태로 시작하지 않습니다. 서버를 종료합니다.", e
        )
        sys.exit(1)

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
    logger.info("  Webhook:      %s:%d/webhook", CONFIG["bind_host"], CONFIG["port"])
    logger.info("  Metrics:      %s:%d/metrics", CONFIG["bind_host"], CONFIG["port"])
    logger.info("  Events API:   %s:%d/api/v1/events", CONFIG["bind_host"], CONFIG["port"])
    logger.info("  Isolations:   %s:%d/api/v1/isolations", CONFIG["bind_host"], CONFIG["port"])
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
        (CONFIG["bind_host"], CONFIG["port"]),
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
