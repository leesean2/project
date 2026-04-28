#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

IMAGE_NAME="compliance-response-server"
IMAGE_TAG="latest"
CLUSTER_NAME="compliance-platform"

echo "============================================"
echo " Step 3: Response Server Deployment"
echo " (kind 클러스터 내부에서 실행)"
echo "============================================"

# 1. Build Docker image
echo "[1/5] Building Docker image..."
docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" "${PROJECT_DIR}/response-server/"

# 2. Load into kind cluster
echo "[2/5] Loading image into kind cluster..."
kind load docker-image "${IMAGE_NAME}:${IMAGE_TAG}" --name "${CLUSTER_NAME}"

# 3. Apply manifests
echo "[3/5] Applying Kubernetes manifests..."
kubectl apply -f "${PROJECT_DIR}/manifests/response-server.yaml"

# 4. Wait for deployment
echo "[4/5] Waiting for Response Server to be ready..."
kubectl rollout status deployment/response-server \
    -n compliance-system --timeout=60s

# 5. Health check
echo "[5/5] Health check..."
sleep 3
RS_PORT=$(docker ps --format '{{.Ports}}' 2>/dev/null | grep -oP '0\.0\.0\.0:\K[0-9]+(?=->30500)' | head -1)
RS_PORT="${RS_PORT:-5000}"

if curl -s "http://127.0.0.1:${RS_PORT}/healthz" 2>/dev/null | grep -q "ok"; then
    echo "  Response Server: HEALTHY (port ${RS_PORT})"
else
    echo "  [WARN] Health check failed — server may need more time"
fi

echo ""
echo "--- Pods ---"
kubectl get pods -n compliance-system -o wide
echo ""
echo "--- Services ---"
kubectl get svc -n compliance-system
echo ""
echo "============================================"
echo " Response Server deployment complete!"
echo ""
echo " API endpoints (via port ${RS_PORT}):"
echo "   curl http://localhost:${RS_PORT}/healthz"
echo "   curl http://localhost:${RS_PORT}/metrics"
echo "   curl http://localhost:${RS_PORT}/api/v1/events/summary"
echo "   curl http://localhost:${RS_PORT}/api/v1/isolations"
echo "============================================"
