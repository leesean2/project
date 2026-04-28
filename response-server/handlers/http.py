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
"""

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("handler")

# Webhook 요청 본문 상한 — 이를 초과하면 HMAC 검증 전에 413으로 거부
_MAX_BODY_SIZE = 1 * 1024 * 1024  # 1 MB


class RequestHandler(BaseHTTPRequestHandler):
    """
    Combined webhook + REST API handler.

    Uses server.processor, server.store, server.metrics, server.kube
    injected via the HTTPServer subclass.
    """

    def log_message(self, fmt, *args):
        """Suppress default access log (we use structured logging)."""
        pass

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
            if content_length <= 0:
                self._send_json(400, {"error": "empty body"})
                return

            # Body 크기 상한 검사 — HMAC 검증 전 단계에서 DoS 방어
            if content_length > _MAX_BODY_SIZE:
                remote_addr = self.client_address[0] if self.client_address else ""
                logger.warning(
                    "Webhook rejected: body_too_large content_length=%d ip=%s",
                    content_length, remote_addr,
                )
                self.server.metrics.inc_webhook_rejected(413, "body_too_large")
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
                    # reason을 함께 전달해 사유별 메트릭을 세분화
                    self.server.metrics.inc_webhook_rejected(status_code, reason)
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
        self.end_headers()
        self.wfile.write(body)

    # ─── Events API ───────────────────────────────────────

    def _handle_list_events(self):
        """
        GET /api/v1/events?severity=high&namespace=default&limit=50
        """
        params = parse_qs(urlparse(self.path).query)
        store = self.server.store

        severity = params.get("severity", [None])[0]
        namespace = params.get("namespace", [None])[0]
        limit = int(params.get("limit", ["50"])[0])

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
        summary = self.server.store.get_summary()
        self._send_json(200, summary)

    def _handle_get_event(self, event_id: str):
        """GET /api/v1/events/:id"""
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
        params = parse_qs(urlparse(self.path).query)
        namespace = params.get("namespace", [""])[0]
        policies = self.server.kube.list_isolation_policies(namespace)
        self._send_json(200, {
            "count": len(policies),
            "policies": policies,
        })

    def _handle_delete_isolation(self, namespace: str, policy_name: str):
        """DELETE /api/v1/isolations/:ns/:name — remove isolation."""
        success = self.server.kube.delete_isolation_policy(namespace, policy_name)
        if success:
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
        """
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = {}
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
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # CORS for dashboard access
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status: int, text: str):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
