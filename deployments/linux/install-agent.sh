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
ARTIFACT_HEADERS=$(mktemp)
curl --fail --silent --show-error -D "$ARTIFACT_HEADERS" "$HUB_URL/downloads/linux/sentinel-agent" -o "$INSTALL_DIR/sentinel-agent"
EXPECTED_SHA=$(awk 'BEGIN{IGNORECASE=1} /^X-Checksum-SHA256:/ {gsub("\r", "", $2); print $2}' "$ARTIFACT_HEADERS")
ACTUAL_SHA=$(sha256sum "$INSTALL_DIR/sentinel-agent" | cut -d' ' -f1)
rm -f "$ARTIFACT_HEADERS"
if [ -z "$EXPECTED_SHA" ] || [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
    echo "Fehler: Agent-Binary-Integrität konnte nicht verifiziert werden."
    exit 1
fi
chmod +x "$INSTALL_DIR/sentinel-agent"

# 2. System-Metriken erfassen
HOSTNAME=$(hostname)
OS_VERSION=$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
HARDWARE_UUID=$(cat /sys/class/dmi/id/product_uuid 2>/dev/null || cat /etc/machine-id)

# 3. Enrollment durchführen
echo "[*] Führe automatisches Stimm-Enrollment aus..."
RESPONSE=$(curl --fail --silent --show-error -X POST "$HUB_URL/enroll" \
    -H "Content-Type: application/json" \
    -d "{\"enrollment_token\": \"$ENROLLMENT_TOKEN\", \"hostname\": \"$HOSTNAME\", \"os_version\": \"$OS_VERSION\", \"hardware_uuid\": \"$HARDWARE_UUID\"}")

if ! printf '%s' "$RESPONSE" | grep -q '"status":"ENROLLED"'; then
    echo "Fehler: Enrollment-Antwort ist ungültig."
    exit 1
fi

# 4. Konfiguration schreiben
CERT_DIR="$INSTALL_DIR/certs"
mkdir -p "$CERT_DIR"
chmod 700 "$CERT_DIR"
CLIENT_CERT_B64=$(printf '%s' "$RESPONSE" | grep -o '"client_certificate":"[^"]*' | cut -d'"' -f4)
CLIENT_KEY_B64=$(printf '%s' "$RESPONSE" | grep -o '"client_private_key":"[^"]*' | cut -d'"' -f4)
CA_CERT_B64=$(printf '%s' "$RESPONSE" | grep -o '"ca_certificate":"[^"]*' | cut -d'"' -f4)
if [ -n "$CLIENT_CERT_B64" ] && [ -n "$CLIENT_KEY_B64" ] && [ -n "$CA_CERT_B64" ]; then
    printf '%s' "$CLIENT_CERT_B64" | base64 -d > "$CERT_DIR/client.crt"
    printf '%s' "$CLIENT_KEY_B64" | base64 -d > "$CERT_DIR/client.key"
    printf '%s' "$CA_CERT_B64" | base64 -d > "$CERT_DIR/ca.crt"
    chmod 600 "$CERT_DIR/client.key"
fi
cat <<EOF > "$INSTALL_DIR/config.yaml"
node_id: "$(echo $RESPONSE | grep -o '"agent_id":"[^"]*' | cut -d'"' -f4)"
shared_secret: "$(echo $RESPONSE | grep -o '"mTLS_shared_secret":"[^"]*' | cut -d'"' -f4)"
hub_url: "$HUB_URL"
client_certificate: "$CERT_DIR/client.crt"
client_key: "$CERT_DIR/client.key"
ca_certificate: "$CERT_DIR/ca.crt"
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
