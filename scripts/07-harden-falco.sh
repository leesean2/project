#!/bin/bash
# =============================================================
# Falco Hardening: chattr +i + Heartbeat Watchdog
# =============================================================
# 목적:
#   - chattr +i 로 Falco 바이너리/룰/설정 파일 변조 방지
#   - systemd watchdog 서비스로 30초마다 Falco 생존 확인
#   - 침묵 탐지: Response Server가 heartbeat 미수신 시 CRITICAL 경보
# =============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# --- 보호 대상 파일 목록 ---
FALCO_BINARY="/usr/bin/falco"
FALCO_YAML="/etc/falco/falco.yaml"
FALCO_RULES_DIR="/etc/falco/rules.d"
FALCO_COMPLIANCE_RULES="/etc/falco/rules.d/compliance-rules.yaml"
FALCO_OUTPUT_CONF="/etc/falco/config.d/compliance-output.yaml"
FALCO_SERVICE_DROP_IN="/etc/systemd/system/falco-modern-bpf.service.d/kubeconfig.conf"

CANARY_FILE="/var/run/falco-heartbeat"
WATCHDOG_SCRIPT="/usr/local/bin/falco-watchdog"
WATCHDOG_ENV="/etc/falco/watchdog.env"

echo "============================================"
echo " Step 7: Falco Hardening"
echo " chattr +i + Heartbeat Watchdog"
echo "============================================"

# ─── 0. 전제조건 확인 ─────────────────────────────────────
echo "[0/5] Checking prerequisites..."

if ! command -v falco &>/dev/null; then
    echo "  ERROR: Falco not installed. Run 02-deploy-falco.sh first."
    exit 1
fi

if ! sudo systemctl is-active --quiet falco-modern-bpf; then
    echo "  ERROR: falco-modern-bpf is not running. Start it first."
    exit 1
fi

# Response Server 포트 감지 (kind NodePort 매핑)
RS_PORT=$(docker ps --format '{{.Ports}}' 2>/dev/null \
    | grep -oP '0\.0\.0\.0:\K[0-9]+(?=->30500)' | head -1 || true)
if [ -z "$RS_PORT" ]; then
    RS_PORT="5000"
    echo "  [WARN] Could not detect kind NodePort, using default ${RS_PORT}"
fi
RS_URL="http://127.0.0.1:${RS_PORT}"
echo "  Response Server URL: ${RS_URL}"

# ─── 1. chattr +i 적용 ────────────────────────────────────
echo "[1/5] Applying chattr +i to Falco files..."

lock_file() {
    local f="$1"
    if [ ! -f "$f" ]; then
        echo "  [SKIP] Not found: $f"
        return
    fi
    # 멱등성: 이미 immutable이면 일단 해제 후 재적용
    sudo chattr -i "$f" 2>/dev/null || true
    sudo chattr +i "$f"
    echo "  Locked: $f"
}

lock_file "$FALCO_BINARY"
lock_file "$FALCO_YAML"
lock_file "$FALCO_COMPLIANCE_RULES"
lock_file "$FALCO_OUTPUT_CONF"
[ -f "$FALCO_SERVICE_DROP_IN" ] && lock_file "$FALCO_SERVICE_DROP_IN"

# falcoctl 바이너리 (룰 자동 업데이트 도구 — 공격 벡터가 될 수 있음)
FALCOCTL_BIN="$(which falcoctl 2>/dev/null || true)"
if [ -n "$FALCOCTL_BIN" ]; then
    lock_file "$FALCOCTL_BIN"
fi

echo "  Verifying immutability..."
LOCKED=0
FAILED=0
for f in "$FALCO_BINARY" "$FALCO_YAML" "$FALCO_COMPLIANCE_RULES" "$FALCO_OUTPUT_CONF"; do
    [ -f "$f" ] || continue
    if lsattr "$f" 2>/dev/null | grep -qE "^----i"; then
        LOCKED=$((LOCKED + 1))
    else
        echo "  [WARN] Immutability check failed: $f"
        FAILED=$((FAILED + 1))
    fi
done
echo "  Immutable: ${LOCKED} files locked, ${FAILED} failed"

# ─── 2. Canary 파일 생성 ──────────────────────────────────
echo "[2/5] Setting up heartbeat canary file..."
sudo touch "$CANARY_FILE"
sudo chmod 644 "$CANARY_FILE"
# canary 파일 자체는 immutable로 만들지 않음 (watchdog이 써야 하므로)
echo "  Canary file: $CANARY_FILE"

# ─── 3. Watchdog 환경설정 파일 ───────────────────────────
echo "[3/5] Writing watchdog environment config..."
sudo tee "$WATCHDOG_ENV" > /dev/null << ENV_EOF
RESPONSE_SERVER_URL=${RS_URL}
CANARY_FILE=${CANARY_FILE}
FALCO_SERVICE=falco-modern-bpf
ENV_EOF
echo "  Written: $WATCHDOG_ENV"

# ─── 4. Watchdog 스크립트 + systemd 서비스/타이머 ─────────
echo "[4/5] Installing watchdog service..."

# 4a. watchdog 쉘 스크립트
sudo tee "$WATCHDOG_SCRIPT" > /dev/null << 'WATCHDOG_EOF'
#!/bin/bash
# Falco Watchdog — 30초마다 실행
# 1. Falco 서비스 상태 확인
# 2. canary 파일 touch → Falco가 탐지 → response-server로 heartbeat 이벤트 전달
# 3. Response Server에 직접 watchdog heartbeat POST (경로 이중화)

set -euo pipefail

source /etc/falco/watchdog.env

TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Falco 서비스 상태
if systemctl is-active --quiet "${FALCO_SERVICE}"; then
    FALCO_STATUS="running"
else
    FALCO_STATUS="stopped"
    logger -t falco-watchdog -p daemon.crit \
        "CRITICAL: ${FALCO_SERVICE} is NOT running at ${TIMESTAMP}"
fi

# canary 파일 touch → Falco 탐지 파이프라인 통과 여부 검증
touch "${CANARY_FILE}" 2>/dev/null \
    && logger -t falco-watchdog -p daemon.debug "Canary touched: ${CANARY_FILE}" \
    || logger -t falco-watchdog -p daemon.warn "Could not touch canary file"

# Response Server 직접 heartbeat POST (Falco 파이프라인 우회 경로)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time 5 \
    -X POST "${RESPONSE_SERVER_URL}/api/v1/heartbeat" \
    -H "Content-Type: application/json" \
    -d "{\"source\":\"watchdog\",\"falco_status\":\"${FALCO_STATUS}\",\"ts\":\"${TIMESTAMP}\"}" \
    2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "200" ]; then
    logger -t falco-watchdog -p daemon.debug \
        "Heartbeat sent OK (falco=${FALCO_STATUS})"
else
    logger -t falco-watchdog -p daemon.warn \
        "Could not reach response server (HTTP ${HTTP_CODE})"
fi
WATCHDOG_EOF
sudo chmod 755 "$WATCHDOG_SCRIPT"
echo "  Script: $WATCHDOG_SCRIPT"

# 4b. systemd oneshot service
sudo tee /etc/systemd/system/falco-watchdog.service > /dev/null << 'SVC_EOF'
[Unit]
Description=Falco Watchdog Heartbeat
Documentation=https://falco.org
After=network.target falco-modern-bpf.service
Wants=falco-watchdog.timer

[Service]
Type=oneshot
ExecStart=/usr/local/bin/falco-watchdog
EnvironmentFile=/etc/falco/watchdog.env
StandardOutput=journal
StandardError=journal
SyslogIdentifier=falco-watchdog
SVC_EOF

# 4c. systemd timer (30초 간격)
sudo tee /etc/systemd/system/falco-watchdog.timer > /dev/null << 'TIMER_EOF'
[Unit]
Description=Falco Watchdog Timer (30s interval)
Documentation=https://falco.org

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=1s

[Install]
WantedBy=timers.target
TIMER_EOF

sudo systemctl daemon-reload
sudo systemctl enable --now falco-watchdog.timer
echo "  Timer: falco-watchdog.timer (every 30s)"

# ─── 5. 검증 ──────────────────────────────────────────────
echo "[5/5] Verification..."

# Falco 여전히 실행 중인지
if sudo systemctl is-active --quiet falco-modern-bpf; then
    echo "  Falco: running OK"
else
    echo "  ERROR: Falco stopped after hardening! Check logs."
    exit 1
fi

# Watchdog 타이머 활성화 확인
if sudo systemctl is-active --quiet falco-watchdog.timer; then
    echo "  Watchdog timer: active"
else
    echo "  WARN: Watchdog timer not active"
fi

# 불변성 변조 시도 테스트
echo "  Tampering test: trying to write to $FALCO_BINARY ..."
if sudo bash -c "echo test >> $FALCO_BINARY" 2>/dev/null; then
    echo "  [FAIL] chattr +i did NOT protect $FALCO_BINARY !"
else
    echo "  [OK]  Write blocked by chattr +i"
fi

echo ""
echo "============================================"
echo " Falco Hardening Complete"
echo ""
echo " Protected files (immutable):"
echo "   $FALCO_BINARY"
echo "   $FALCO_YAML"
echo "   $FALCO_COMPLIANCE_RULES"
echo "   $FALCO_OUTPUT_CONF"
echo ""
echo " Heartbeat watchdog:"
echo "   Timer:  falco-watchdog.timer (30s)"
echo "   Script: $WATCHDOG_SCRIPT"
echo "   Log:    journalctl -t falco-watchdog -f"
echo ""
echo " To upgrade Falco, first run:"
echo "   sudo chattr -i $FALCO_BINARY $FALCO_YAML $FALCO_COMPLIANCE_RULES"
echo "   ... then upgrade, then re-run this script"
echo "============================================"
