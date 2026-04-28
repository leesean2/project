#!/bin/bash
# =============================================================
# Falco Signing Proxy 설치 + Webhook HMAC 보안 활성화
# =============================================================
# 목적:
#   1. 랜덤 HMAC 비밀키 생성 (openssl)
#   2. /usr/local/bin/falco-signing-proxy 설치 (Python HTTP 서버)
#   3. falco-signing-proxy.service (systemd) 등록 및 시작
#   4. K8s Secret(webhook-secret) 에 비밀키 주입 → Response Server 재시작
#   5. Falco http_output을 프록시 포트(5001)로 변경 → Falco 재시작
#   6. WEBHOOK_HMAC_REQUIRED=true 로 ConfigMap 패치
#
# 흐름:
#   Falco → 127.0.0.1:5001 (Signing Proxy, HMAC 서명)
#         → 127.0.0.1:<RS_PORT>/webhook (Response Server, 서명 검증)
# =============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PROXY_SCRIPT="/usr/local/bin/falco-signing-proxy"
SECRET_FILE="/etc/falco/webhook.secret"  # root:root 600, chattr +i 로 보호
PROXY_PORT=5001

echo "============================================"
echo " Step 8: Falco Signing Proxy + Webhook HMAC"
echo "============================================"

# ─── 0. 전제조건 ──────────────────────────────────────────
echo "[0/6] Checking prerequisites..."

if ! sudo systemctl is-active --quiet falco-modern-bpf; then
    echo "  ERROR: falco-modern-bpf is not running."
    exit 1
fi

if ! kubectl get namespace compliance-system &>/dev/null; then
    echo "  ERROR: compliance-system namespace not found. Run 03-deploy-response-server.sh first."
    exit 1
fi

RS_PORT=$(docker ps --format '{{.Ports}}' 2>/dev/null \
    | grep -oP '0\.0\.0\.0:\K[0-9]+(?=->30500)' | head -1 || true)
if [ -z "$RS_PORT" ]; then
    RS_PORT="5000"
    echo "  [WARN] Could not detect kind NodePort, using default ${RS_PORT}"
fi
RS_WEBHOOK_URL="http://127.0.0.1:${RS_PORT}/webhook"
echo "  Response Server webhook URL: ${RS_WEBHOOK_URL}"

# ─── 1. HMAC 비밀키 생성 ──────────────────────────────────
echo "[1/6] Generating HMAC secret..."

# 기존 비밀키가 있으면 재사용 (멱등성)
if sudo test -f "$SECRET_FILE" 2>/dev/null; then
    echo "  [REUSE] Existing secret found at $SECRET_FILE"
    WEBHOOK_SECRET="$(sudo cat "$SECRET_FILE")"
else
    WEBHOOK_SECRET="$(openssl rand -hex 32)"
    echo "$WEBHOOK_SECRET" | sudo tee "$SECRET_FILE" > /dev/null
    sudo chmod 600 "$SECRET_FILE"
    sudo chown root:root "$SECRET_FILE"
    echo "  Generated: $SECRET_FILE (600, root:root)"
fi

# chattr +i 로 비밀키 파일 보호 (07-harden-falco.sh 가 실행된 환경 고려)
sudo chattr -i "$SECRET_FILE" 2>/dev/null || true
sudo chattr +i "$SECRET_FILE"
echo "  Secret file locked with chattr +i"

# ─── 2. Signing Proxy 스크립트 설치 ──────────────────────
echo "[2/6] Installing signing proxy..."

sudo tee "$PROXY_SCRIPT" > /dev/null << 'PROXY_EOF'
#!/usr/bin/env python3
"""
Falco Signing Proxy

Falco http_output 이벤트를 받아 HMAC-SHA256 서명 후 Response Server로 전달.

환경 변수:
  WEBHOOK_SECRET   : HMAC 비밀키 (필수)
  FORWARD_URL      : 전달 대상 URL (기본: http://127.0.0.1:5000/webhook)
  SIGNING_PROXY_PORT: 수신 포트 (기본: 5001)
"""

import hashlib
import hmac
import http.server
import logging
import os
import sys
import time
import urllib.error
import urllib.request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] signing-proxy: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

_SECRET = os.environ.get("WEBHOOK_SECRET", "").encode("utf-8")
_FORWARD_URL = os.environ.get("FORWARD_URL", "http://127.0.0.1:5000/webhook")
_PORT = int(os.environ.get("SIGNING_PROXY_PORT", "5001"))
_TIMEOUT = int(os.environ.get("FORWARD_TIMEOUT", "5"))


def _sign(body: bytes) -> tuple[str, str]:
    """HMAC-SHA256(secret, timestamp.body) 계산 후 (sig_hex, timestamp_str) 반환."""
    ts = str(int(time.time()))
    payload = ts.encode() + b"." + body
    sig = hmac.new(_SECRET, payload, hashlib.sha256).hexdigest()
    return f"sha256={sig}", ts


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # 기본 접근 로그 억제
        pass

    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path != "/webhook":
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        sig_header, ts_header = _sign(body)

        req = urllib.request.Request(_FORWARD_URL, data=body, method="POST")
        req.add_header(
            "Content-Type",
            self.headers.get("Content-Type", "application/json"),
        )
        req.add_header("X-Webhook-Signature", sig_header)
        req.add_header("X-Webhook-Timestamp", ts_header)
        # 서명 프록시가 127.0.0.1 임을 Response Server에게 알림
        req.add_header("X-Forwarded-For", "127.0.0.1")
        req.add_header("X-Forwarded-By", "falco-signing-proxy/1.0")

        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                resp_body = resp.read()
                logger.debug("Forwarded → HTTP %d", resp.status)
                self.send_response(resp.status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(resp_body)
        except urllib.error.HTTPError as exc:
            logger.warning("Forward HTTP error: %d", exc.code)
            self.send_response(exc.code)
            self.end_headers()
        except Exception as exc:
            logger.error("Forward failed: %s", exc)
            self.send_response(502)
            self.end_headers()


def main() -> None:
    if not _SECRET:
        logger.error("WEBHOOK_SECRET is empty — cannot sign webhooks. Exiting.")
        sys.exit(1)

    server = http.server.HTTPServer(("127.0.0.1", _PORT), _Handler)
    logger.info(
        "Signing proxy listening on 127.0.0.1:%d → %s",
        _PORT, _FORWARD_URL,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
PROXY_EOF

sudo chmod 755 "$PROXY_SCRIPT"
echo "  Installed: $PROXY_SCRIPT"

# ─── 3. systemd 서비스 등록 ───────────────────────────────
echo "[3/6] Registering systemd service..."

sudo tee /etc/systemd/system/falco-signing-proxy.service > /dev/null << SVC_EOF
[Unit]
Description=Falco Webhook Signing Proxy
Documentation=https://falco.org
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/falco-signing-proxy
EnvironmentFile=/etc/falco/signing-proxy.env
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=falco-signing-proxy

# 최소 권한 (읽기 전용 FS, no privileges)
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SVC_EOF

# 환경 파일 (비밀키는 파일에서 직접 읽음)
sudo tee /etc/falco/signing-proxy.env > /dev/null << ENV_EOF
WEBHOOK_SECRET=${WEBHOOK_SECRET}
FORWARD_URL=${RS_WEBHOOK_URL}
SIGNING_PROXY_PORT=${PROXY_PORT}
FORWARD_TIMEOUT=5
ENV_EOF
sudo chmod 600 /etc/falco/signing-proxy.env
sudo chown root:root /etc/falco/signing-proxy.env

sudo systemctl daemon-reload
sudo systemctl enable --now falco-signing-proxy
sleep 2

if sudo systemctl is-active --quiet falco-signing-proxy; then
    echo "  falco-signing-proxy: running on port ${PROXY_PORT}"
else
    echo "  ERROR: falco-signing-proxy failed to start!"
    sudo journalctl -u falco-signing-proxy --no-pager -n 20
    exit 1
fi

# ─── 4. K8s Secret 주입 → Response Server 재시작 ─────────
echo "[4/6] Injecting secret into K8s + restarting Response Server..."

# 기존 Secret을 새 비밀키로 교체
kubectl create secret generic webhook-secret \
    --from-literal=WEBHOOK_SECRET="${WEBHOOK_SECRET}" \
    --namespace=compliance-system \
    --dry-run=client -o yaml | kubectl apply -f -

# WEBHOOK_HMAC_REQUIRED=true 로 ConfigMap 패치
kubectl patch configmap response-server-config \
    --namespace=compliance-system \
    --type merge \
    --patch '{"data":{"WEBHOOK_HMAC_REQUIRED":"true"}}'

# Pod 재시작으로 새 설정 반영
kubectl rollout restart deployment/response-server -n compliance-system
kubectl rollout status deployment/response-server -n compliance-system --timeout=60s
echo "  Response Server restarted with HMAC enabled"

# ─── 5. Falco http_output을 프록시 포트로 재설정 ──────────
echo "[5/6] Reconfiguring Falco http_output → signing proxy port ${PROXY_PORT}..."

# compliance-output.yaml의 immutable 해제 후 수정 후 재적용
sudo chattr -i /etc/falco/config.d/compliance-output.yaml 2>/dev/null || true

sudo tee /etc/falco/config.d/compliance-output.yaml > /dev/null << CONF_EOF
json_output: true
json_include_output_property: true
json_include_tags_property: true
priority: NOTICE

http_output:
  enabled: true
  url: http://127.0.0.1:${PROXY_PORT}/webhook
  user_agent: falco-compliance-platform
CONF_EOF

# 수정 후 다시 immutable 적용
sudo chattr +i /etc/falco/config.d/compliance-output.yaml
echo "  Falco http_output → http://127.0.0.1:${PROXY_PORT}/webhook"

sudo systemctl restart falco-modern-bpf
sleep 2

if sudo systemctl is-active --quiet falco-modern-bpf; then
    echo "  Falco restarted OK"
else
    echo "  ERROR: Falco failed after reconfiguration!"
    sudo journalctl -u falco-modern-bpf --no-pager -n 20
    exit 1
fi

# ─── 6. 동작 검증 ─────────────────────────────────────────
echo "[6/6] Verification..."

# 서명 프록시 healthz
if curl -sf http://127.0.0.1:${PROXY_PORT}/healthz > /dev/null 2>&1; then
    echo "  Signing proxy /healthz: OK"
else
    echo "  [WARN] Signing proxy not responding"
fi

# HMAC 없이 직접 요청 → 401 확인
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "http://127.0.0.1:${RS_PORT}/webhook" \
    -H "Content-Type: application/json" \
    -d '{"test":"forge_attempt"}' 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "401" ]; then
    echo "  HMAC enforcement: OK (forge attempt returned 401)"
elif [ "$HTTP_CODE" = "000" ]; then
    echo "  [WARN] Could not reach response server for verification"
else
    echo "  [WARN] Unexpected status ${HTTP_CODE} for unsigned request (expected 401)"
    echo "         WEBHOOK_HMAC_REQUIRED might not be active yet — check rollout"
fi

echo ""
echo "============================================"
echo " Webhook Security Active"
echo ""
echo " HMAC:          SHA-256 (replay window: 5min)"
echo " Signing proxy: 127.0.0.1:${PROXY_PORT}"
echo " Secret file:   ${SECRET_FILE} (immutable)"
echo ""
echo " Logs:"
echo "   journalctl -u falco-signing-proxy -f"
echo ""
echo " Test forge (should return 401):"
echo "   curl -s -o /dev/null -w '%{http_code}' -X POST \\"
echo "     http://127.0.0.1:${RS_PORT}/webhook \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"fake\":\"event\"}'"
echo "============================================"
