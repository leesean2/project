#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Detect Response Server port
RS_PORT=$(docker ps --format '{{.Ports}}' 2>/dev/null | grep -oP '0\.0\.0\.0:\K[0-9]+(?=->30500)' | head -1)
RS_PORT="${RS_PORT:-5000}"

echo "============================================"
echo " Runtime Detection Test Suite"
echo " Response Server: http://127.0.0.1:${RS_PORT}"
echo "============================================"
echo ""

# ─── Setup test pods ──────────────────────────────────
echo -e "${CYAN}[SETUP] Deploying test workloads...${NC}"
kubectl apply -f "${PROJECT_DIR}/manifests/test-workloads.yaml"
sleep 5
kubectl wait --for=condition=ready pod -l tier=test \
    -n test-workloads --timeout=60s 2>/dev/null || \
    echo -e "${YELLOW}[WARN] Some pods may still be starting${NC}"

# Record event count before tests
BEFORE=$(curl -s "http://127.0.0.1:${RS_PORT}/api/v1/events/summary" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['total_events'])" 2>/dev/null || echo "0")
echo "  Events before tests: ${BEFORE}"
echo ""

# ─── TEST 1: Sensitive File Read ──────────────────────
echo -e "${YELLOW}[TEST 1] Sensitive File Read (/etc/shadow)${NC}"
echo "  ISMS-P: 2.6.1 | Expected: medium"
kubectl exec -n test-workloads vulnerable-app -- cat /etc/shadow 2>/dev/null || true
echo -e "${GREEN}  -> Executed${NC}"
sleep 3

# ─── TEST 2: Shell Spawn ─────────────────────────────
echo -e "${YELLOW}[TEST 2] Shell Spawn in Container${NC}"
echo "  ISMS-P: 2.6.1 | Expected: medium"
kubectl exec -it -n test-workloads vulnerable-app -- sh -c "echo shell-test" 2>/dev/null || true
echo -e "${GREEN}  -> Executed${NC}"
sleep 3

# ─── TEST 3: Reconnaissance ──────────────────────────
echo -e "${YELLOW}[TEST 3] Reconnaissance Activity${NC}"
echo "  ISMS-P: 2.11.4 | Expected: low~medium"
kubectl exec -n test-workloads recon-target -- sh -c "whoami" 2>/dev/null || true
kubectl exec -n test-workloads recon-target -- sh -c "id" 2>/dev/null || true
kubectl exec -n test-workloads recon-target -- sh -c "cat /etc/resolv.conf" 2>/dev/null || true
echo -e "${GREEN}  -> Executed${NC}"
sleep 3

# ─── TEST 4: Write to Monitored Directory ────────────
echo -e "${YELLOW}[TEST 4] Write to /usr/bin (Persistence)${NC}"
echo "  ISMS-P: 2.11.1 | Expected: medium"
kubectl exec -n test-workloads recon-target -- \
    sh -c "echo '#!/bin/sh' > /usr/bin/malicious && chmod +x /usr/bin/malicious && echo '  -> /usr/bin/malicious created'" 2>/dev/null || \
    echo "  -> write blocked"
kubectl exec -n test-workloads recon-target -- \
    sh -c "touch /etc/cron.d/persist 2>/dev/null && echo '  -> /etc/cron.d/persist created'" 2>/dev/null || true
echo -e "${GREEN}  -> Executed${NC}"
sleep 3

# ─── RESULTS ──────────────────────────────────────────
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN} Results (Response Server API)${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

AFTER=$(curl -s "http://127.0.0.1:${RS_PORT}/api/v1/events/summary" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['total_events'])" 2>/dev/null || echo "0")
NEW_EVENTS=$((AFTER - BEFORE))
echo -e "${YELLOW}New events detected: ${NEW_EVENTS}${NC}"
echo ""

echo -e "${YELLOW}Event summary:${NC}"
curl -s "http://127.0.0.1:${RS_PORT}/api/v1/events/summary" 2>/dev/null | \
    python3 -m json.tool 2>/dev/null | head -25 || \
    echo "  (Could not reach Response Server API)"

echo ""
echo -e "${YELLOW}Recent test-workloads events:${NC}"
kubectl logs -n compliance-system -l app=response-server --tail=300 | \
    grep "test-workloads" | tail -10 || echo "  (No events)"

echo ""
echo "============================================"
echo " Test suite complete!"
echo "============================================"
