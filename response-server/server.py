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

# =============================================================
# Configuration — 환경변수 섹션별 분리
# =============================================================
# ── [1] 서버 기본 설정 ──────────────────────────────────────
_SERVER_PORT        = int(os.getenv("SERVER_PORT", "5000"))
_AUTO_ISOLATE       = os.getenv("AUTO_ISOLATE", "true").lower() == "true"
_LOG_LEVEL          = os.getenv("LOG_LEVEL", "INFO")
_EVENT_STORE_SIZE   = int(os.getenv("EVENT_STORE_SIZE", "2000"))

# ── [2] AI 분류기 설정 ──────────────────────────────────────
_AI_ENDPOINT        = os.getenv("AI_ENDPOINT", "")
_AI_TIMEOUT         = int(os.getenv("AI_TIMEOUT", "5"))
_AI_CONF_THRESHOLD  = float(os.getenv("AI_CONFIDENCE_THRESHOLD", "0.6"))
_FB_CONF_THRESHOLD  = float(os.getenv("FALLBACK_CONFIDENCE_THRESHOLD", "0.35"))

# ── [3] 오탐(FP) 완화 임계값 ────────────────────────────────
# fp_score >= FP_SUPPRESS_THRESHOLD  → fp_suppressed (로그만)
# fp_score >= FP_DOWNGRADE_THRESHOLD → severity 한 단계 하향
_FP_SUPPRESS        = float(os.getenv("FP_SUPPRESS_THRESHOLD", "0.75"))
_FP_DOWNGRADE       = float(os.getenv("FP_DOWNGRADE_THRESHOLD", "0.45"))

# ── [4] Falco 침묵 탐지 ─────────────────────────────────────
# N초 동안 이벤트 없으면 CRITICAL 경보 (watchdog 주기=30s → 임계=90s)
_HB_SILENCE         = int(os.getenv("HEARTBEAT_SILENCE_THRESHOLD", "90"))
_HB_INTERVAL        = int(os.getenv("HEARTBEAT_CHECK_INTERVAL", "30"))

# ── [5] Webhook 보안 (HMAC / IP / Rate-limit) ────────────────
# WEBHOOK_SECRET      : HMAC 공유 비밀키 (signing-proxy와 동일)
#                       비어 있으면 HMAC 검증 완전 비활성화
# WEBHOOK_HMAC_REQUIRED: "true" → 서명 없는 요청 즉시 거부 (hard mode, 기본값)
#                        "false" → 서명 있으면 검증, 없으면 통과 (soft mode)
# WEBHOOK_IP_WHITELIST : 허용 CIDR 목록 (콤마 구분). 빈 값이면 비활성화.
# RATE_LIMIT_CAPACITY  : IP당 burst 허용 요청 수
# RATE_LIMIT_REFILL_RATE: IP당 초당 토큰 충전 속도 (지속 RPS)
_HMAC_SECRET        = os.getenv("WEBHOOK_SECRET", "")
_HMAC_REQUIRED      = os.getenv("WEBHOOK_HMAC_REQUIRED", "true").lower() == "true"
_IP_WHITELIST       = [
    ip.strip()
    for ip in os.getenv("WEBHOOK_IP_WHITELIST", "").split(",")
    if ip.strip()
]
_RL_CAPACITY        = int(os.getenv("RATE_LIMIT_CAPACITY", "100"))
_RL_REFILL_RATE     = float(os.getenv("RATE_LIMIT_REFILL_RATE", "3.0"))

CONFIG = {
    # [1] 서버
    "port":                         _SERVER_PORT,
    "auto_isolate":                 _AUTO_ISOLATE,
    "log_level":                    _LOG_LEVEL,
    "event_store_size":             _EVENT_STORE_SIZE,
    # [2] AI
    "ai_endpoint":                  _AI_ENDPOINT,
    "ai_timeout":                   _AI_TIMEOUT,
    "ai_confidence_threshold":      _AI_CONF_THRESHOLD,
    "fallback_confidence_threshold": _FB_CONF_THRESHOLD,
    # [3] FP 완화
    "fp_suppress_threshold":        _FP_SUPPRESS,
    "fp_downgrade_threshold":       _FP_DOWNGRADE,
    # [4] 침묵 탐지
    "heartbeat_silence_threshold":  _HB_SILENCE,
    "heartbeat_check_interval":     _HB_INTERVAL,
    # [5] Webhook 보안
    "webhook_secret":               _HMAC_SECRET,
    "webhook_hmac_required":        _HMAC_REQUIRED,
    "webhook_ip_whitelist":         _IP_WHITELIST,
    "rate_limit_capacity":          _RL_CAPACITY,
    "rate_limit_refill_rate":       _RL_REFILL_RATE,
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


def main():
    """Initialize all modules and start servers."""

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
    # HMAC 모드를 Prometheus 게이지에 즉시 기록 (대시보드에서 확인 가능)
    metrics.set_hmac_mode(CONFIG["webhook_hmac_required"])
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
