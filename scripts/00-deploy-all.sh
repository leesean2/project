#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "╔══════════════════════════════════════════════════╗"
echo "║  Policy-as-Code Compliance Platform              ║"
echo "║  Runtime Detection — Full Deployment             ║"
echo "║                                                  ║"
echo "║  Architecture:                                   ║"
echo "║  Falco (WSL2 host) → Response Server (kind)     ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Step 1: Kind cluster
echo "━━━ Step 1/3: Kind Cluster ━━━"
bash "${SCRIPT_DIR}/01-setup-cluster.sh"
echo ""

# Step 2: Response Server (must be up before Falco sends events)
echo "━━━ Step 2/3: Response Server (kind) ━━━"
bash "${SCRIPT_DIR}/03-deploy-response-server.sh"
echo ""

# Step 3: Falco (host, connects to Response Server via NodePort)
echo "━━━ Step 3/4: Falco (host) ━━━"
bash "${SCRIPT_DIR}/02-deploy-falco.sh"
echo ""

# Step 4: Webhook HMAC 서명 프록시 (보안 활성화 먼저)
echo "━━━ Step 4/5: Webhook Signing Proxy + HMAC ━━━"
bash "${SCRIPT_DIR}/08-setup-signing-proxy.sh"
echo ""

# Step 5: Falco hardening (chattr +i + watchdog, 마지막에 설정 잠금)
echo "━━━ Step 5/5: Falco Hardening ━━━"
bash "${SCRIPT_DIR}/07-harden-falco.sh"
echo ""

# ─── Verify ───────────────────────────────────────────
echo "━━━ Verification ━━━"
echo ""

RS_PORT=$(docker ps --format '{{.Ports}}' 2>/dev/null | grep -oP '0\.0\.0\.0:\K[0-9]+(?=->30500)' | head -1)
RS_PORT="${RS_PORT:-5000}"

echo "  Falco:           $(sudo systemctl is-active falco-modern-bpf 2>/dev/null || echo 'unknown')"
echo "  Watchdog timer:  $(sudo systemctl is-active falco-watchdog.timer 2>/dev/null || echo 'unknown')"
echo "  Response Server: $(curl -s http://127.0.0.1:${RS_PORT}/healthz 2>/dev/null || echo 'unreachable')"
echo "  Falco status:    $(curl -s http://127.0.0.1:${RS_PORT}/api/v1/falco/status 2>/dev/null || echo 'unreachable')"
echo "  Kind Pods:"
kubectl get pods -n compliance-system -o wide 2>/dev/null || true
echo ""

echo "╔══════════════════════════════════════════════════╗"
echo "║  Deployment Complete!                            ║"
echo "║                                                  ║"
echo "║  Test:    ./scripts/04-run-tests.sh             ║"
echo "║  Demo:    ./scripts/06-attack-demo.sh           ║"
echo "║                                                  ║"
echo "║  Falco logs:                                     ║"
echo "║    sudo journalctl -u falco-modern-bpf -f       ║"
echo "║  Watchdog logs:                                  ║"
echo "║    journalctl -t falco-watchdog -f              ║"
echo "║  Response Server logs:                           ║"
echo "║    kubectl logs -n compliance-system -l app=response-server -f ║"
echo "║  API:                                            ║"
echo "║    curl localhost:${RS_PORT}/api/v1/events/summary        ║"
echo "║    curl localhost:${RS_PORT}/api/v1/falco/status          ║"
echo "║    curl localhost:${RS_PORT}/api/v1/isolations            ║"
echo "║    curl localhost:${RS_PORT}/metrics                      ║"
echo "╚══════════════════════════════════════════════════╝"
