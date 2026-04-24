#!/bin/bash
set -euo pipefail

CLUSTER_NAME="compliance-platform"

echo "============================================"
echo " Step 1: Kind Cluster Setup"
echo "============================================"

if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    echo "[INFO] Cluster '${CLUSTER_NAME}' already exists."
    kubectl cluster-info --context "kind-${CLUSTER_NAME}" 2>/dev/null || true
    exit 0
fi

echo "[1/3] Creating kind cluster config..."
cat > /tmp/kind-config.yaml << 'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: compliance-platform
nodes:
  - role: control-plane
    extraPortMappings:
      # Response Server (Falco http_output → here)
      - containerPort: 30500
        hostPort: 5000
        protocol: TCP
      # Grafana
      - containerPort: 30300
        hostPort: 3000
        protocol: TCP
      # Prometheus
      - containerPort: 30900
        hostPort: 9090
        protocol: TCP
  - role: worker
  - role: worker
EOF

echo "[2/3] Creating kind cluster..."
kind create cluster --config /tmp/kind-config.yaml --wait 120s

echo "[3/3] Verifying cluster..."
kubectl get nodes
echo ""
echo "============================================"
echo " Cluster '${CLUSTER_NAME}' is ready!"
echo "============================================"
