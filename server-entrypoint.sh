#!/bin/sh
set -e

# Configuration (required)
if [ -z "${CHISEL_AUTH:-}" ]; then
    echo "ERROR: CHISEL_AUTH environment variable is required!"
    echo ""
    echo "Generate a unique credential (e.g., broker:\$(openssl rand -base64 32))"
    echo "and set it via -e CHISEL_AUTH=... when starting the container."
    exit 1
fi

echo "========================================="
echo "     ZeroPath Broker Server v1.0"
echo "========================================="
echo "© 2025 ZeroPath Corp. - zeropath.com"
echo ""
echo "Chisel Port: 8443 (TLS encrypted)"
echo "Proxy Port: 1080 (opens after client connect)"
echo "========================================="
echo ""

# Generate self-signed certificate for TLS
CERT_DIR="/tmp/certs"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

if [ ! -f server.key ] || [ ! -f server.crt ]; then
    echo "[ZeroPath] Generating TLS certificate..."
    
    # Generate private key
    openssl genrsa -out server.key 2048 2>/dev/null
    
    # Generate self-signed certificate
    openssl req -new -x509 -sha256 -key server.key -out server.crt -days 365 \
      -subj "/C=US/ST=CA/L=SF/O=ZeroPath Corp/CN=broker.zeropath.com" 2>/dev/null
    
    echo "[ZeroPath] ✓ TLS certificate generated"
else
    echo "[ZeroPath] Using existing TLS certificate material"
fi
echo ""
echo "[ZeroPath] Starting secure broker server..."
echo "[ZeroPath] Waiting for client connections..."
echo ""

# Start chisel with the generated certificates
# --tls-key and --tls-cert enable TLS encryption
exec /usr/local/bin/chisel server \
    --host 0.0.0.0 \
    --port 8443 \
    --reverse \
    --auth "$CHISEL_AUTH" \
    --tls-key /tmp/certs/server.key \
    --tls-cert /tmp/certs/server.crt
