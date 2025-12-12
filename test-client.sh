#!/bin/sh
set -e

IMAGE_NAME="broker-client-test"

SERVER_ADDR="${BROKER_SERVER:-}"
if [ -z "$SERVER_ADDR" ]; then
    echo -n "Enter broker server address (host:port): "
    read SERVER_ADDR
fi

if [ -z "$SERVER_ADDR" ]; then
    echo "ERROR: Broker server address is required." >&2
    exit 1
fi

if [ -z "${CHISEL_AUTH:-}" ]; then
    echo -n "Enter CHISEL_AUTH credential (username:password): "
    read -r CHISEL_AUTH
fi

if [ -z "$CHISEL_AUTH" ]; then
    echo "ERROR: CHISEL_AUTH credential is required." >&2
    exit 1
fi

echo "========================================="
echo "     ZeroPath Broker Client Test"
echo "========================================="
echo "© 2025 ZeroPath Corp. - zeropath.com"
echo ""

# Build the image
echo "[ZeroPath] Building client image: ${IMAGE_NAME}"
docker build -t "${IMAGE_NAME}" -f Dockerfile.client . > /dev/null 2>&1
echo "[ZeroPath] ✓ Image built successfully"
echo ""

# Choose test mode
echo "Select test mode:"
echo "1) Full network proxy (unrestricted)"
echo "2) Network/IP restricted proxy"
echo "3) Specific port forwarding only"
echo "4) Proxy with blocked ports"
echo ""
echo -n "Enter choice (1-4) [default: 1]: "
read CHOICE

case "${CHOICE:-1}" in
    1)
        echo ""
        echo "[ZeroPath] Running: Full network proxy (unrestricted)"
        echo "========================================="
        docker run --rm \
            -e BROKER_SERVER="${SERVER_ADDR}" \
            -e CHISEL_AUTH="${CHISEL_AUTH}" \
            -e BROKER_MODE="socks" \
            "${IMAGE_NAME}"
        ;;
        
    2)
        echo ""
        echo "[ZeroPath] Running: Network/IP restricted proxy"
        echo "[ZeroPath] Allowed: 192.168.1.0/24, 10.0.0.0/16, 10.0.137.151"
        echo "========================================="
        docker run --rm \
            --cap-add=NET_ADMIN \
            -e BROKER_SERVER="${SERVER_ADDR}" \
            -e CHISEL_AUTH="${CHISEL_AUTH}" \
            -e BROKER_MODE="socks" \
            -e ALLOWED_NETWORKS="192.168.1.0/24,10.0.0.0/16,10.0.137.151" \
            "${IMAGE_NAME}"
        ;;
        
    3)
        echo ""
        echo "[ZeroPath] Running: Specific port forwarding mode"
        echo "[ZeroPath] Only forwarding:"
        echo "  • Port 8080 → 192.168.1.126:80 (Pi-hole)"
        echo "  • Port 8443 → 192.168.1.126:443 (Pi-hole HTTPS)"
        echo "  • Port 3306 → 192.168.1.100:3306 (MySQL)"
        echo "========================================="
        docker run --rm \
            -e BROKER_SERVER="${SERVER_ADDR}" \
            -e CHISEL_AUTH="${CHISEL_AUTH}" \
            -e BROKER_MODE="ports" \
            -e ALLOWED_TARGETS="8080:192.168.1.126:80,8443:192.168.1.126:443,3306:192.168.1.100:3306" \
            "${IMAGE_NAME}"
        ;;
        
    4)
        echo ""
        echo "[ZeroPath] Running: Proxy with blocked ports"
        echo "[ZeroPath] Blocking ports: 22 (SSH), 3389 (RDP), 445 (SMB)"
        echo "========================================="
        docker run --rm \
            --cap-add=NET_ADMIN \
            -e BROKER_SERVER="${SERVER_ADDR}" \
            -e CHISEL_AUTH="${CHISEL_AUTH}" \
            -e BROKER_MODE="socks" \
            -e BLOCKED_PORTS="22,3389,445" \
            "${IMAGE_NAME}"
        ;;
        
    *)
        echo "[ZeroPath] Invalid choice. Using default (full proxy)."
        docker run --rm \
            -e BROKER_SERVER="${SERVER_ADDR}" \
            -e CHISEL_AUTH="${CHISEL_AUTH}" \
            "${IMAGE_NAME}"
        ;;
esac
