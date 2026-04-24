#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================"
echo " Step 2: Falco Host Installation"
echo " (WSL2 호스트에서 modern_ebpf로 실행)"
echo "============================================"

# ─── 1. Check BTF support ─────────────────────────────
echo "[1/6] Checking BTF support..."
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "  BTF: OK (/sys/kernel/btf/vmlinux exists)"
else
    echo "  ERROR: BTF not available. modern_ebpf will not work."
    echo "  See README.md for WSL2 kernel build instructions."
    exit 1
fi

# ─── 2. Install Falco ─────────────────────────────────
echo "[2/6] Installing Falco..."
if command -v falco &>/dev/null; then
    echo "  Falco already installed: $(falco --version 2>/dev/null | head -1)"
else
    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
        sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg 2>/dev/null

    echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
https://download.falco.org/packages/deb stable main" | \
        sudo tee /etc/apt/sources.list.d/falcosecurity.list >/dev/null

    sudo apt update -qq
    sudo FALCO_FRONTEND=noninteractive apt install -y falco
fi

# ─── 3. Deploy custom compliance rules ────────────────
echo "[3/6] Deploying ISMS-P compliance rules..."
sudo mkdir -p /etc/falco/rules.d
sudo cp "${PROJECT_DIR}/falco/compliance-rules.yaml" /etc/falco/rules.d/compliance-rules.yaml
echo "  Installed: /etc/falco/rules.d/compliance-rules.yaml"

# ─── 4. Configure http_output ─────────────────────────
echo "[4/6] Configuring Falco output..."

# Detect Response Server port (kind NodePort mapping)
RS_PORT=$(docker ps --format '{{.Ports}}' 2>/dev/null | grep -oP '0\.0\.0\.0:\K[0-9]+(?=->30500)' | head -1)
if [ -z "$RS_PORT" ]; then
    RS_PORT="5000"
    echo "  [WARN] Could not detect kind port mapping, using default ${RS_PORT}"
fi
echo "  Response Server URL: http://127.0.0.1:${RS_PORT}/webhook"

sudo tee /etc/falco/config.d/compliance-output.yaml > /dev/null << CONF_EOF
json_output: true
json_include_output_property: true
json_include_tags_property: true
priority: NOTICE

http_output:
  enabled: true
  url: http://127.0.0.1:${RS_PORT}/webhook
  user_agent: falco-compliance-platform
CONF_EOF

# Also enable http_output in main falco.yaml (override default disabled)
sudo sed -i '/^http_output:/,/user_agent:/{
  s/enabled: false/enabled: true/
}' /etc/falco/falco.yaml
sudo sed -i "s|^  url: \"\"|  url: \"http://127.0.0.1:${RS_PORT}/webhook\"|" /etc/falco/falco.yaml

# ─── 5. Configure KUBECONFIG for K8s metadata ─────────
echo "[5/6] Configuring KUBECONFIG for Falco..."
KUBE_CONFIG="${HOME}/.kube/config"
if [ -f "$KUBE_CONFIG" ]; then
    sudo mkdir -p /etc/systemd/system/falco-modern-bpf.service.d
    sudo tee /etc/systemd/system/falco-modern-bpf.service.d/kubeconfig.conf > /dev/null << SYSD_EOF
[Service]
Environment="KUBECONFIG=${KUBE_CONFIG}"
SYSD_EOF
    echo "  KUBECONFIG: ${KUBE_CONFIG}"
else
    echo "  [WARN] ${KUBE_CONFIG} not found. K8s metadata may not resolve."
fi

# ─── 6. Validate rules and start ──────────────────────
echo "[6/6] Validating rules and starting Falco..."
if sudo /usr/bin/falco -o engine.kind=modern_ebpf --dry-run 2>&1 | grep -q "Error"; then
    echo "  ERROR: Rule validation failed!"
    sudo /usr/bin/falco -o engine.kind=modern_ebpf --dry-run 2>&1 | grep "Error"
    exit 1
fi
echo "  Rules: OK"

sudo systemctl daemon-reload
sudo systemctl restart falco-modern-bpf
sleep 2

if sudo systemctl is-active --quiet falco-modern-bpf; then
    echo ""
    echo "============================================"
    echo " Falco is running (modern_ebpf)"
    echo ""
    echo " Status:  sudo systemctl status falco-modern-bpf"
    echo " Logs:    sudo journalctl -u falco-modern-bpf -f"
    echo " Rules:   /etc/falco/rules.d/compliance-rules.yaml"
    echo " Config:  /etc/falco/config.d/compliance-output.yaml"
    echo "============================================"
else
    echo "  ERROR: Falco failed to start!"
    sudo journalctl -u falco-modern-bpf --no-pager -n 20
    exit 1
fi
