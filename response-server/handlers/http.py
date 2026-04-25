"""
HTTP request handlers.

Endpoints:
  POST /webhook              — Falco Sidekick webhook receiver
  GET  /healthz              — Health check
  GET  /readyz               — Readiness check
  GET  /metrics              — Prometheus metrics

  GET  /api/v1/events         — List recent events (with filters)
  GET  /api/v1/events/summary — Aggregated summary for dashboard
  GET  /api/v1/events/:id     — Single event detail

  GET  /api/v1/isolations           — List active isolation NetworkPolicies
  DELETE /api/v1/isolations/:ns/:name — Remove isolation (un-isolate pod)

  POST /api/v1/heartbeat     — Watchdog heartbeat (falco-watchdog systemd service)
  GET  /api/v1/falco/status  — Falco heartbeat / silence detection status

Security changes (vs original):
  [HIGH #4] POST /api/v1/heartbeat  — HEARTBEAT_TOKEN HMAC 인증 추가
  [HIGH #5] DELETE /api/v1/isolations — API_TOKEN Bearer 인증 추가
  [HIGH #6] CORS Access-Control-Allow-Origin — 와일드카드(*) → 환경변수 화이트리스트
  [MEDIUM #7] GET /api/v1/events?limit — 최대 500건 상한 추가
"""

import hmac
import json
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("handler")

# ─── 인증 설정 (환경변수에서 주입) ─────────────────────────────
# ConfigMap: HEARTBEAT_TOKEN, API_TOKEN, ALLOWED_ORIGINS
# Secret:    WEBHOOK_SECRET (webhook security 모듈에서 별도 처리)

# POST /api/v1/heartbeat 인증 토큰
_HEARTBEAT_TOKEN: str = os.environ.get("HEARTBEAT_TOKEN", "")

# DELETE /api/v1/isolations + GET /api/v1/* 인증 토큰
_API_TOKEN: str = os.environ.get("API_TOKEN", "")

# CORS 허용 오리진 목록 (쉼표 구분)
# 예: "http://localhost:3000,http://grafana.monitoring.svc:3000"
_ALLOWED_ORIGINS: list[str] = [
    o.strip()
    for o in os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if o.strip()
]

# GET /api/v1/events?limit 최대 허용값
_MAX_EVENT_LIMIT: int = 500

# [CRITICAL] 요청 바디 최대 허용 크기 — 무제한 읽기로 인한 메모리 소진 DoS 방지
_MAX_WEBHOOK_BODY_BYTES: int = 1 * 1024 * 1024   # 1 MB
_MAX_HEARTBEAT_BODY_BYTES: int = 64 * 1024        # 64 KB

# ─── 공개 읽기 API 속도 제한 (토큰 버킷, IP당) ──────────────────
# burst: 최대 순간 요청 수, refill: 초당 충전 속도
_READ_RL_BURST: int = int(os.environ.get("READ_RATE_LIMIT_BURST", "30"))
_READ_RL_REFILL: float = float(os.environ.get("READ_RATE_LIMIT_REFILL", "1.0"))


_READ_RL_MAX_BUCKETS: int = 20_000


class _ReadRateLimiter:
    """IP당 토큰 버킷 속도 제한기 (공개 GET API 전용)."""

    def __init__(self, capacity: int, refill_rate: float):
        self._capacity = float(capacity)
        self._refill = refill_rate
        self._buckets: dict = {}
        self._lock = threading.Lock()

    def is_allowed(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if ip in self._buckets:
                tokens, last = self._buckets[ip]
                tokens = min(self._capacity, tokens + (now - last) * self._refill)
            else:
                # [HIGH] 버킷 수 상한 초과 시 새 IP 거부 — 메모리 소진 방지
                if len(self._buckets) >= _READ_RL_MAX_BUCKETS:
                    return False
                tokens = self._capacity

            if tokens >= 1.0:
                self._buckets[ip] = (tokens - 1.0, now)
                return True
            self._buckets[ip] = (tokens, now)
            return False


_read_rate_limiter = _ReadRateLimiter(_READ_RL_BURST, _READ_RL_REFILL)


def _mask_ip(ip: str) -> str:
    """로그 프라이버시 보호 — IPv4 마지막 옥텟, IPv6 뒷부분을 마스킹."""
    if not ip:
        return "unknown"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.***"
    return ip[:8] + "***"


def _constant_time_eq(a: str, b: str) -> bool:
    """타이밍 공격 방지를 위한 상수 시간 문자열 비교."""
    return hmac.compare_digest(
        a.encode("utf-8"),
        b.encode("utf-8"),
    )


class RequestHandler(BaseHTTPRequestHandler):
    """
    Combined webhook + REST API handler.

    Uses server.processor, server.store, server.metrics, server.kube
    injected via the HTTPServer subclass.
    """

    def log_message(self, fmt, *args):
        """Suppress default access log (we use structured logging)."""
        pass

    def _client_ip(self) -> str:
        """로그용 마스킹된 클라이언트 IP 반환."""
        return _mask_ip(self.client_address[0] if self.client_address else "")

    def _check_read_rate(self) -> bool:
        """공개 읽기 API 속도 제한 검사. 초과 시 429 응답 후 False 반환."""
        ip = self.client_address[0] if self.client_address else ""
        if not _read_rate_limiter.is_allowed(ip):
            logger.warning("Read rate limit exceeded: ip=%s", _mask_ip(ip))
            self._send_json(429, {"error": "too many requests"})
            return False
        return True

    # ─── Routing ──────────────────────────────────────────

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/webhook":
            self._handle_webhook()
        elif path == "/api/v1/heartbeat":
            self._handle_watchdog_heartbeat()
        else:
            self._send_json(404, {"error": "not found"})

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/healthz":
            self._send_text(200, "ok")
        elif path == "/readyz":
            self._send_text(200, "ready")
        elif path == "/metrics":
            self._handle_metrics()
        elif path == "/api/v1/events":
            self._handle_list_events()
        elif path == "/api/v1/events/summary":
            self._handle_event_summary()
        elif path.startswith("/api/v1/events/"):
            event_id = path.split("/")[-1]
            self._handle_get_event(event_id)
        elif path == "/api/v1/isolations":
            self._handle_list_isolations()
        elif path == "/api/v1/falco/status":
            self._handle_falco_status()
        else:
            self._send_json(404, {"error": "not found"})

    def do_DELETE(self):
        path = urlparse(self.path).path

        # [HIGH #5] DELETE는 API_TOKEN Bearer 인증 필요
        if not self._check_api_auth():
            return

        # DELETE /api/v1/isolations/:namespace/:policy_name
        if path.startswith("/api/v1/isolations/"):
            parts = path.split("/")
            # ['', 'api', 'v1', 'isolations', ns, name]
            if len(parts) == 6:
                ns, name = parts[4], parts[5]
                self._handle_delete_isolation(ns, name)
            else:
                self._send_json(400, {"error": "expected /api/v1/isolations/:ns/:name"})
        else:
            self._send_json(404, {"error": "not found"})

    # ─── 인증 헬퍼 ────────────────────────────────────────

    def _check_api_auth(self) -> bool:
        """
        [HIGH #5] Bearer 토큰 인증.

        Authorization: Bearer <API_TOKEN> 헤더 검증.
        API_TOKEN이 비어있으면 서버 설정 오류로 간주하여 503 반환.
        인증 실패 시 401을 반환하고 False를 리턴.
        """
        if not _API_TOKEN:
            logger.critical(
                "API_TOKEN is not set — refusing all authenticated requests. "
                "Set API_TOKEN environment variable."
            )
            self._send_json(503, {"error": "server misconfiguration: API_TOKEN not set"})
            return False

        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            logger.warning(
                "API auth failed: missing Bearer token from %s",
                self._client_ip(),
            )
            self._send_json(401, {"error": "unauthorized: Bearer token required"})
            return False

        provided_token = auth_header[len("Bearer "):]
        if not _constant_time_eq(provided_token, _API_TOKEN):
            logger.warning(
                "API auth failed: invalid token from %s",
                self._client_ip(),
            )
            self._send_json(401, {"error": "unauthorized: invalid token"})
            return False

        return True

    def _check_heartbeat_auth(self) -> bool:
        """
        [HIGH #4] Heartbeat 전용 토큰 인증.

        X-Watchdog-Token: <HEARTBEAT_TOKEN> 헤더 검증.
        HEARTBEAT_TOKEN이 비어있으면 503 반환.
        """
        if not _HEARTBEAT_TOKEN:
            logger.critical(
                "HEARTBEAT_TOKEN is not set — refusing heartbeat requests. "
                "Set HEARTBEAT_TOKEN environment variable."
            )
            self._send_json(503, {"error": "server misconfiguration: HEARTBEAT_TOKEN not set"})
            return False

        provided = self.headers.get("X-Watchdog-Token", "")
        if not provided:
            logger.warning(
                "Heartbeat auth failed: missing X-Watchdog-Token from %s",
                self._client_ip(),
            )
            self._send_json(401, {"error": "unauthorized: X-Watchdog-Token required"})
            return False

        if not _constant_time_eq(provided, _HEARTBEAT_TOKEN):
            logger.warning(
                "Heartbeat auth failed: invalid token from %s",
                self._client_ip(),
            )
            self._send_json(401, {"error": "unauthorized: invalid heartbeat token"})
            return False

        return True

    # ─── Webhook Handler ──────────────────────────────────

    def _handle_webhook(self):
        """
        Receive Falco event and process asynchronously.

        보안 검사 순서:
          1. 요청 본문 읽기
          2. WebhookSecurity.validate() — Rate limit → IP whitelist → HMAC
          3. JSON 파싱 → 비동기 처리
        """
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                self._send_json(400, {"error": "empty body"})
                return
            # [CRITICAL] 바디 크기 상한 — 메모리 소진 DoS 방지
            if content_length > _MAX_WEBHOOK_BODY_BYTES:
                self._send_json(413, {"error": "request body too large"})
                return

            body = self.rfile.read(content_length)

            # ── 보안 검사 ──────────────────────────────────
            security = getattr(self.server, "security", None)
            if security is not None:
                headers = {k: v for k, v in self.headers.items()}
                remote_addr = self.client_address[0] if self.client_address else ""
                allowed, status_code, reason = security.validate(
                    remote_addr=remote_addr,
                    headers=headers,
                    body=body,
                )
                if not allowed:
                    logger.warning(
                        "Webhook rejected: status=%d reason=%s ip=%s",
                        status_code, reason, remote_addr,
                    )
                    self.server.metrics.inc_webhook_rejected(status_code)
                    self._send_json(status_code, {"error": reason})
                    return
            # ───────────────────────────────────────────────

            event = json.loads(body.decode("utf-8"))

            # Process in background so Falco doesn't timeout
            processor = self.server.processor
            thread = threading.Thread(
                target=self._safe_process,
                args=(processor, event),
                daemon=True,
            )
            thread.start()

            self._send_json(200, {"status": "accepted"})

        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid json"})
        except Exception as e:
            logger.error("Webhook error: %s", e, exc_info=True)
            self._send_json(500, {"error": "internal error"})

    @staticmethod
    def _safe_process(processor, event):
        """Process event with exception catching."""
        try:
            processor.process(event)
        except Exception as e:
            logger.error("Event processing failed: %s", e, exc_info=True)

    # ─── Metrics ──────────────────────────────────────────

    def _handle_metrics(self):
        body = self.server.metrics.render().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # [LOW] 보안 헤더 — MIME 스니핑·클릭재킹·캐시 노출 방지
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    # ─── Events API ───────────────────────────────────────

    def _handle_list_events(self):
        """
        GET /api/v1/events?severity=high&namespace=default&limit=50

        [MEDIUM #7] limit 파라미터 최대값 _MAX_EVENT_LIMIT(500)으로 제한.
        음수 또는 비정수 값은 기본값(50)으로 대체.
        """
        if not self._check_read_rate():
            return
        params = parse_qs(urlparse(self.path).query)
        store = self.server.store

        severity = params.get("severity", [None])[0]
        namespace = params.get("namespace", [None])[0]

        # [MEDIUM #7] limit 검증
        try:
            limit = int(params.get("limit", ["50"])[0])
            if limit <= 0:
                limit = 50
            limit = min(limit, _MAX_EVENT_LIMIT)  # 최대 500건 상한
        except (ValueError, TypeError):
            limit = 50

        if severity:
            events = store.get_by_severity(severity)
        elif namespace:
            events = store.get_by_namespace(namespace)
        else:
            events = store.get_recent(limit)

        self._send_json(200, {
            "count": len(events),
            "events": events[:limit],
        })

    def _handle_event_summary(self):
        """GET /api/v1/events/summary — dashboard aggregation."""
        if not self._check_read_rate():
            return
        summary = self.server.store.get_summary()
        self._send_json(200, summary)

    def _handle_get_event(self, event_id: str):
        """GET /api/v1/events/:id"""
        if not self._check_read_rate():
            return
        event = self.server.store.get_by_id(event_id)
        if event:
            self._send_json(200, event)
        else:
            self._send_json(404, {"error": f"event {event_id} not found"})

    # ─── Isolations API ───────────────────────────────────

    def _handle_list_isolations(self):
        """
        GET /api/v1/isolations?namespace=test-workloads
        """
        if not self._check_read_rate():
            return
        params = parse_qs(urlparse(self.path).query)
        namespace = params.get("namespace", [""])[0]
        policies = self.server.kube.list_isolation_policies(namespace)
        self._send_json(200, {
            "count": len(policies),
            "policies": policies,
        })

    def _handle_delete_isolation(self, namespace: str, policy_name: str):
        """
        DELETE /api/v1/isolations/:ns/:name — remove isolation.
        인증은 do_DELETE()에서 _check_api_auth()로 사전 처리됨.
        """
        success = self.server.kube.delete_isolation_policy(namespace, policy_name)
        if success:
            logger.info(
                "Isolation deleted by API: %s/%s from %s",
                namespace, policy_name,
                self._client_ip(),
            )
            self._send_json(200, {
                "status": "deleted",
                "namespace": namespace,
                "policy": policy_name,
            })
        else:
            self._send_json(500, {
                "error": f"failed to delete {namespace}/{policy_name}",
            })

    # ─── Falco Health / Heartbeat ─────────────────────────

    def _handle_watchdog_heartbeat(self):
        """
        POST /api/v1/heartbeat — falco-watchdog systemd 서비스에서 30초마다 호출.
        Falco 프로세스 생존 여부를 직접 전달하는 독립 경로.

        [HIGH #4] X-Watchdog-Token 헤더로 HEARTBEAT_TOKEN 검증.
        인증 실패 시 401 반환, heartbeat 기록하지 않음.
        """
        # [HIGH #4] 인증 먼저
        if not self._check_heartbeat_auth():
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = {}
            if content_length > _MAX_HEARTBEAT_BODY_BYTES:
                # [CRITICAL] 인증 후에도 과도한 바디 크기 거부
                self._send_json(413, {"error": "request body too large"})
                return
            if content_length > 0:
                raw = self.rfile.read(content_length)
                body = json.loads(raw.decode("utf-8"))

            falco_status = body.get("falco_status", "unknown")
            source = body.get("source", "unknown")

            heartbeat = getattr(self.server, "heartbeat", None)
            if heartbeat:
                heartbeat.record_watchdog(falco_status)

            logger.debug(
                "Watchdog heartbeat: source=%s falco=%s", source, falco_status
            )
            self._send_json(200, {
                "status": "ok",
                "falco_status": falco_status,
            })

        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid json"})
        except Exception as e:
            logger.error("Heartbeat handler error: %s", e)
            self._send_json(500, {"error": "internal error"})

    def _handle_falco_status(self):
        """
        GET /api/v1/falco/status — Falco heartbeat 및 침묵 탐지 상태 조회.
        Prometheus 외에 REST로도 확인 가능한 엔드포인트.
        """
        heartbeat = getattr(self.server, "heartbeat", None)
        if heartbeat is None:
            self._send_json(503, {"error": "heartbeat monitor not initialized"})
            return

        status = heartbeat.get_status()
        http_status = 200 if status["status"] == "healthy" else 503
        self._send_json(http_status, status)

    # ─── Response Helpers ─────────────────────────────────

    def _send_json(self, status: int, data: dict):
        """
        [HIGH #6] CORS: Access-Control-Allow-Origin을 와일드카드(*)에서
        ALLOWED_ORIGINS 환경변수 기반 화이트리스트로 변경.

        요청의 Origin 헤더가 허용 목록에 있으면 해당 오리진을 반환.
        없으면 허용 목록의 첫 번째 오리진을 반환 (브라우저가 CORS 차단함).
        """
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))

        # [보안 헤더] 클릭재킹·MIME 스니핑·캐시 노출 방지
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")

        # [HIGH #6] CORS 화이트리스트 처리
        request_origin = self.headers.get("Origin", "")
        if request_origin in _ALLOWED_ORIGINS:
            allowed_origin = request_origin
        else:
            # 허용되지 않은 오리진 → 첫 번째 허용 오리진 반환
            # 브라우저는 오리진 불일치로 CORS 차단, 서버는 정상 응답
            allowed_origin = _ALLOWED_ORIGINS[0] if _ALLOWED_ORIGINS else ""

        if allowed_origin:
            self.send_header("Access-Control-Allow-Origin", allowed_origin)
            self.send_header("Vary", "Origin")  # 프록시 캐시 오염 방지

        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status: int, text: str):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # [보안 헤더] 클릭재킹·MIME 스니핑 방지
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)
