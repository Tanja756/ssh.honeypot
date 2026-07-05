#!/usr/bin/env bash
set -euo pipefail

NAME="ssh-honeypot"
SRC_DIR="/opt/${NAME}"
SERVICE_FILE="/etc/systemd/system/${NAME}.service"
LOG_DIR="/var/lib/${NAME}"

if [[ $EUID -ne 0 ]]; then
    echo "[-] This script must be run as root." >&2
    exit 1
fi

echo "[+] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip gosu >/dev/null

echo "[+] Installing Python packages..."
pip3 install -q -r "$(dirname "$0")/requirements.txt"

echo "[+] Creating ${SRC_DIR}..."
mkdir -p "${SRC_DIR}"
cp -a "$(dirname "$0")"/* "${SRC_DIR}/"
chown -R nobody:nogroup "${SRC_DIR}"

echo "[+] Creating ${LOG_DIR}..."
mkdir -p "${LOG_DIR}"
chown nobody:nogroup "${LOG_DIR}"

echo "[+] Installing systemd service..."
cp "${SRC_DIR}/${NAME}.service" "${SERVICE_FILE}"
systemctl daemon-reload

if systemctl is-enabled "${NAME}" &>/dev/null; then
    echo "[+] Restarting ${NAME}..."
    systemctl restart "${NAME}"
else
    echo "[+] Enabling and starting ${NAME}..."
    systemctl enable --now "${NAME}"
fi

echo "[+] Status:"
systemctl status "${NAME}" --no-pager 2>&1 | head -10

echo ""
echo "[✔] Deployment complete."
