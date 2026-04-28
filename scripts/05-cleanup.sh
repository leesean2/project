#!/bin/bash
set -euo pipefail

echo "============================================"
echo " Cleanup — Remove Test Resources"
echo "============================================"

echo "[1/4] Removing isolation NetworkPolicies..."
for ns in test-workloads production default; do
    kubectl delete networkpolicies -n "$ns" \
        -l managed-by=compliance-response-server 2>/dev/null || true
done

echo "[2/4] Removing test workloads..."
kubectl delete namespace test-workloads --ignore-not-found=true 2>/dev/null || true

echo "[3/4] Removing production test namespace..."
kubectl delete namespace production --ignore-not-found=true 2>/dev/null || true

echo "[4/4] Removing test pods in default namespace..."
kubectl delete pod test-victim --ignore-not-found=true 2>/dev/null || true

echo ""
echo " Done. Remaining components:"
echo "   Falco:           sudo systemctl status falco-modern-bpf"
echo "   Response Server: kubectl get pods -n compliance-system"
echo ""
echo " To fully uninstall:"
echo "   sudo systemctl stop falco-modern-bpf"
echo "   sudo systemctl disable falco-modern-bpf"
echo "   kubectl delete -f manifests/response-server.yaml"
echo "   kind delete cluster --name compliance-platform"
echo "============================================"
