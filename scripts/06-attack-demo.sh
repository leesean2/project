#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Detect Response Server port
RS_PORT=$(docker ps --format '{{.Ports}}' 2>/dev/null | grep -oP '0\.0\.0\.0:\K[0-9]+(?=->30500)' | head -1)
RS_PORT="${RS_PORT:-5000}"

echo "╔══════════════════════════════════════════════════╗"
echo "║  HIGH Severity Attack Demo                       ║"
echo "║  nmap in production → AUTO ISOLATION             ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ─── Setup ────────────────────────────────────────────
echo -e "${CYAN}[SETUP] Preparing attack environment...${NC}"
kubectl create namespace production --dry-run=client -o yaml | kubectl apply -f -

# Clean previous isolation policies
kubectl delete networkpolicies -n production \
    -l managed-by=compliance-response-server 2>/dev/null || true

# Delete existing attack pod if any
kubectl delete pod attack-pod -n production --force --grace-period=0 2>/dev/null || true
sleep 2

# Deploy fresh attack pod with nmap
kubectl run attack-pod --image=alpine:3.19 --namespace=production \
    --labels="app=attack-pod" --restart=Never -- sleep infinity
kubectl wait --for=condition=ready pod/attack-pod -n production --timeout=60s

echo "  Installing nmap..."
kubectl exec -n production attack-pod -- apk add --no-cache nmap >/dev/null 2>&1

echo "  Target: production/attack-pod (with nmap)"
echo ""

# Record state before attack
BEFORE_NP=$(kubectl get networkpolicy -n production -l managed-by=compliance-response-server --no-headers 2>/dev/null | wc -l)
echo -e "${YELLOW}NetworkPolicies before attack: ${BEFORE_NP}${NC}"
echo ""

# ─── Attack Stages ────────────────────────────────────
echo -e "${RED}========================================${NC}"
echo -e "${RED} Stage 1: Initial Reconnaissance${NC}"
echo -e "${RED}========================================${NC}"
kubectl exec -n production attack-pod -- sh -c "whoami && id" 2>/dev/null || true
sleep 2

echo ""
echo -e "${RED}========================================${NC}"
echo -e "${RED} Stage 2: Credential Harvesting${NC}"
echo -e "${RED}========================================${NC}"
kubectl exec -n production attack-pod -- cat /etc/shadow 2>/dev/null || true
sleep 2

echo ""
echo -e "${RED}========================================${NC}"
echo -e "${RED} Stage 3: Network Scan (nmap)${NC}"
echo -e "${RED}  → This triggers HIGH severity!${NC}"
echo -e "${RED}========================================${NC}"
kubectl exec -n production attack-pod -- nmap -sT 10.96.0.1 -p 443 2>/dev/null || true
sleep 5

echo ""
echo -e "${RED}========================================${NC}"
echo -e "${RED} Stage 4: Persistence Attempt${NC}"
echo -e "${RED}  → Write malicious binary to /usr/bin${NC}"
echo -e "${RED}========================================${NC}"
echo ""
echo -e "${YELLOW}  [4a] Creating fake backdoor in /usr/bin...${NC}"
kubectl exec -n production attack-pod -- sh -c "echo '#!/bin/sh' > /usr/bin/backdoor && chmod +x /usr/bin/backdoor && echo '  -> /usr/bin/backdoor created'" 2>/dev/null || echo "  -> write blocked"

echo -e "${YELLOW}  [4b] Modifying /usr/sbin (binary tampering)...${NC}"
kubectl exec -n production attack-pod -- sh -c "touch /usr/sbin/.hidden-shell && echo '  -> /usr/sbin/.hidden-shell created'" 2>/dev/null || echo "  -> write blocked"

echo -e "${YELLOW}  [4c] Installing cron persistence...${NC}"
kubectl exec -n production attack-pod -- sh -c "mkdir -p /etc/cron.d && echo '* * * * * root /usr/bin/backdoor' > /etc/cron.d/persist && echo '  -> /etc/cron.d/persist created'" 2>/dev/null || echo "  -> write blocked"

echo -e "${GREEN}  Persistence attempts completed — Falco should detect writes to monitored dirs${NC}"
sleep 3

# ─── Verification ─────────────────────────────────────
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN} Verification${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# NetworkPolicies created?
AFTER_NP=$(kubectl get networkpolicy -n production -l managed-by=compliance-response-server --no-headers 2>/dev/null | wc -l)
echo -e "${YELLOW}[1] NetworkPolicies after attack: ${AFTER_NP}${NC}"
if [ "$AFTER_NP" -gt "$BEFORE_NP" ]; then
    echo -e "${GREEN}    AUTO-ISOLATION TRIGGERED!${NC}"
    kubectl get networkpolicy -n production -l managed-by=compliance-response-server
else
    echo -e "${RED}    No new isolation policies (check Response Server logs)${NC}"
fi
echo ""

# Response Server classification logs
echo -e "${YELLOW}[2] HIGH severity events:${NC}"
kubectl logs -n compliance-system -l app=response-server --tail=500 | \
    grep -i "HIGH.*production\|isolat.*production" | tail -10 || \
    echo "  (No HIGH events found)"
echo ""

# API — isolation list
echo -e "${YELLOW}[3] Active Isolations (API):${NC}"
curl -s "http://127.0.0.1:${RS_PORT}/api/v1/isolations" 2>/dev/null | \
    python3 -m json.tool 2>/dev/null || echo "  (API unreachable)"
echo ""

# API — event summary
echo -e "${YELLOW}[4] Event Summary (API):${NC}"
curl -s "http://127.0.0.1:${RS_PORT}/api/v1/events/summary" 2>/dev/null | \
    python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f\"  Total events: {d['total_events']}\")
print(f\"  By severity:  {d['by_severity']}\")
print(f\"  High events:  {d['by_severity'].get('high', 0)}\")
" 2>/dev/null || echo "  (API unreachable)"

# NetworkPolicy detail
echo ""
echo -e "${YELLOW}[5] Isolation Policy Detail:${NC}"
kubectl get networkpolicy -n production -l managed-by=compliance-response-server \
    -o jsonpath='{range .items[*]}  {.metadata.name}: {.metadata.annotations.compliance\.platform/reason}{"\n"}{end}' 2>/dev/null || true

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Demo Complete!                                  ║"
echo "║                                                  ║"
echo "║  Cleanup:  ./scripts/05-cleanup.sh              ║"
echo "║  Un-isolate a pod:                               ║"
echo "║    curl -X DELETE localhost:${RS_PORT}/api/v1/isolations/production/<policy-name>"
echo "╚══════════════════════════════════════════════════╝"
