#!/usr/bin/env bash
set -euo pipefail

NAME="ssh-honeypot"
SRC_DIR="/opt/${NAME}"
SERVICE_FILE="/etc/systemd/system/${NAME}.service"
LOG_DIR="/var/log/${NAME}"

if [[ $EUID -ne 0 ]]; then
    echo "[-] This script must be run as root." >&2
    exit 1
fi

DASHBOARD_SERVICE_FILE="/etc/systemd/system/${NAME}-dashboard.service"
GEOIP_DB="${SRC_DIR}/GeoLite2-City.mmdb"

echo "[+] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip gosu curl >/dev/null

echo "[+] Installing Python packages..."
pip3 install -q -r "$(dirname "$0")/requirements.txt"

# ── Stop old services ──────────────────────────────────────────
for svc in "${NAME}" "${NAME}-dashboard"; do
    if systemctl is-active "${svc}" &>/dev/null; then
        echo "[+] Stopping ${svc}..."
        systemctl stop "${svc}"
    fi
done

echo "[+] Cleaning ${SRC_DIR}..."
if [[ -d "${SRC_DIR}" ]]; then
    find "${SRC_DIR}" -mindepth 1 -not -name 'GeoLite2-City.mmdb' -delete
fi

echo "[+] Creating ${SRC_DIR}..."
mkdir -p "${SRC_DIR}"
cp -a "$(dirname "$0")/." "${SRC_DIR}/"
chown -R nobody:nogroup "${SRC_DIR}"

echo "[+] Creating ${LOG_DIR}..."
mkdir -p "${LOG_DIR}"
chown nobody:nogroup "${LOG_DIR}"

# ── GeoLite2 ──────────────────────────────────────────────────
if [[ ! -f "${GEOIP_DB}" ]]; then
    echo "[+] Downloading GeoLite2-City.mmdb ..."
    if curl -sL -o "${GEOIP_DB}" "https://git.io/GeoLite2-City.mmdb" 2>/dev/null; then
        echo "[+] GeoLite2 downloaded (${GEOIP_DB})"
    else
        echo "[!] GeoLite2 download failed — dashboard country map disabled."
        echo "    Download manually from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
        echo "    and place at: ${GEOIP_DB}"
    fi
fi

echo "[+] Installing systemd services..."
cp "${SRC_DIR}/${NAME}.service" "${SERVICE_FILE}"
cp "${SRC_DIR}/dashboard.service" "${DASHBOARD_SERVICE_FILE}"
systemctl daemon-reload

for svc in "${NAME}" "${NAME}-dashboard"; do
    echo "[+] Enabling and starting ${svc}..."
    systemctl enable --now "${svc}" 2>&1 || echo "[-] Failed to start ${svc}"
done

# Allow services a moment to settle
sleep 2

echo "[+] Status:"
for svc in "${NAME}" "${NAME}-dashboard"; do
    echo "--- ${svc} ---"
    systemctl status "${svc}" --no-pager 2>&1 | head -8
    if ! systemctl is-active --quiet "${svc}"; then
        echo "  [!] ${svc} is NOT running. Recent logs:"
        journalctl -u "${svc}" --no-pager -n 10 2>&1 | sed 's/^/  /'
    fi
    echo ""
done

echo "[✔] Deployment complete."
