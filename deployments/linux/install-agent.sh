#!/usr/bin/env bash
set -e

ENROLLMENT_TOKEN="${1:-}"
HUB_URL="${2:-https://hub.sentinel-core.local:8443}"

if [ -z "$ENROLLMENT_TOKEN" ]; then
    echo "Fehler: Enrollment-Token nicht übergeben."
    echo "Verwendung: sudo ./install-agent.sh <DEIN_TOKEN> [HUB_URL]"
    exit 1
fi

echo "[*] Starte SentinelCore Linux Agent Setup..."

INSTALL_DIR="/opt/sentinel"
mkdir -p "$INSTALL_DIR"

# 1. Binary herunterladen
echo "[*] Lade Agenten-Binary herunter..."
curl -k -sSL "$HUB_URL/downloads/linux/sentinel-agent" -o "$INSTALL_DIR/sentinel-agent"
chmod +x "$INSTALL_DIR/sentinel-agent"

# 2. System-Metriken erfassen
HOSTNAME=$(hostname)
OS_VERSION=$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
HARDWARE_UUID=$(cat /sys/class/dmi/id/product_uuid 2>/dev/null || cat /etc/machine-id)

# 3. Enrollment durchführen
echo "[*] Führe automatisches Stimm-Enrollment aus..."
RESPONSE=$(curl -k -s -X POST "$HUB_URL/enroll" \
    -H "Content-Type: application/json" \
    -d "{\"enrollment_token\": \"$ENROLLMENT_TOKEN\", \"hostname\": \"$HOSTNAME\", \"os_version\": \"$OS_VERSION\", \"hardware_uuid\": \"$HARDWARE_UUID\"}")

# 4. Konfiguration schreiben
cat <<EOF > "$INSTALL_DIR/config.yaml"
node_id: "$(echo $RESPONSE | grep -o '"agent_id":"[^"]*' | cut -d'"' -f4)"
shared_secret: "$(echo $RESPONSE | grep -o '"mTLS_shared_secret":"[^"]*' | cut -d'"' -f4)"
hub_url: "$HUB_URL"
EOF

# 5. Systemd Service einrichten (Mit Hardened Sandboxing gemäss Security Trust Page)
cat <<EOF > /etc/systemd/system/sentinel-agent.service
[Unit]
Description=SentinelCore Security & Compliance Agent
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/sentinel-agent --config $INSTALL_DIR/config.yaml
Restart=always
RestartSec=10
ProtectSystem=strict
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now sentinel-agent.service

echo "[+] Linux Agent erfolgreich installiert und gestartet!"
