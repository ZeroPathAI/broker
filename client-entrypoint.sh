#!/bin/sh
set -e

if [ -z "$BROKER_SERVER" ]; then
    echo "ERROR: BROKER_SERVER environment variable is required!"
    echo ""
    echo "Usage:"
    echo "  docker run -e BROKER_SERVER=broker.example.com:8443 <image>"
    echo ""
    exit 1
fi

if [ -z "${CHISEL_AUTH:-}" ]; then
    echo "ERROR: CHISEL_AUTH environment variable is required!"
    echo ""
    echo "Generate a unique credential (e.g., broker:\$(openssl rand -base64 32))"
    echo "and set it via -e CHISEL_AUTH=... when starting the container."
    exit 1
fi

BROKER_MODE="${BROKER_MODE:-socks}"  # socks or ports
ALLOWED_TARGETS="${ALLOWED_TARGETS:-}"  # For port mode: "8080:192.168.1.1:80,3306:192.168.1.2:3306"
ALLOWED_NETWORKS="${ALLOWED_NETWORKS:-}"  # CIDR ranges or IPs: "192.168.1.0/24,10.0.0.50,172.16.0.0/12"
BLOCKED_PORTS="${BLOCKED_PORTS:-}"  # Ports to block: "22,3389,445"

require_net_admin() {
    if ! iptables -L >/dev/null 2>&1; then
        echo "ERROR: Network restrictions require NET_ADMIN capability and permission to manage iptables."
        echo "       Re-run the container with --cap-add=NET_ADMIN (and typically as root)."
        exit 1
    fi
}

apply_iptables() {
    if ! iptables "$@"; then
        echo "ERROR: Failed to execute iptables command: iptables $*"
        exit 1
    fi
}

echo "========================================="
echo "     ZeroPath Broker Client v1.0"
echo "========================================="
echo "© 2025 ZeroPath Corp. - zeropath.com"
echo ""
echo "Server: $BROKER_SERVER"
if [ "$BROKER_MODE" = "ports" ]; then
    echo "Mode: Specific port forwarding"
else
    echo "Mode: Full network proxy"
fi
if [ -n "$ALLOWED_NETWORKS" ]; then
    echo "Allowed destinations: $ALLOWED_NETWORKS"
fi
if [ -n "$BLOCKED_PORTS" ]; then
    echo "Blocked ports: $BLOCKED_PORTS"
fi
if [ -n "$ALLOWED_TARGETS" ] && [ "$BROKER_MODE" = "ports" ]; then
    echo "Port forwards: $ALLOWED_TARGETS"
fi
echo "========================================="
echo ""

# Apply network restrictions if specified
if [ -n "$ALLOWED_NETWORKS" ] || [ -n "$BLOCKED_PORTS" ]; then
    echo "[ZeroPath] Applying network access policy..."
    require_net_admin
    
    # Block specific ports first
    if [ -n "$BLOCKED_PORTS" ]; then
        for port in $(echo $BLOCKED_PORTS | tr "," " "); do
            apply_iptables -I OUTPUT -p tcp --dport "$port" -j REJECT
            echo "[ZeroPath] ✓ Blocked port $port"
        done
    fi
    
    # Allow only specific networks/IPs
    if [ -n "$ALLOWED_NETWORKS" ]; then
        for dest in $(echo $ALLOWED_NETWORKS | tr "," " "); do
            # Check if it's a CIDR or single IP
            if echo "$dest" | grep -q "/"; then
                apply_iptables -A OUTPUT -d "$dest" -j ACCEPT
                echo "[ZeroPath] ✓ Allowed network $dest"
            else
                # Single IP - add /32 for iptables
                apply_iptables -A OUTPUT -d "$dest/32" -j ACCEPT
                echo "[ZeroPath] ✓ Allowed host $dest"
            fi
        done
        # Block everything else
        apply_iptables -A OUTPUT -j REJECT
        echo "[ZeroPath] ✓ Blocked all other destinations"
    fi
    echo ""
fi

echo "[ZeroPath] Initializing secure tunnel..."
echo "[ZeroPath] Establishing encrypted connection..."
echo ""

# Force HTTPS connection for encryption
if ! echo "$BROKER_SERVER" | grep -q "^https://"; then
    BROKER_SERVER="https://$BROKER_SERVER"
fi

# Build the chisel command based on mode
if [ "$BROKER_MODE" = "ports" ] && [ -n "$ALLOWED_TARGETS" ]; then
    # Port forwarding mode - specific services only
    echo "[ZeroPath] Creating tunnels for specified services..."
    
    # Build reverse port forward arguments
    REVERSE_ARGS=""
    for target in $(echo $ALLOWED_TARGETS | tr "," " "); do
        REVERSE_ARGS="$REVERSE_ARGS R:$target"
        echo "[ZeroPath] • Forward: $target"
    done
    echo ""
    
    exec /usr/local/bin/chisel client \
        --auth "$CHISEL_AUTH" \
        --tls-skip-verify \
        "$BROKER_SERVER" \
        $REVERSE_ARGS
else
    # Full proxy mode
    echo "[ZeroPath] Creating reverse tunnel..."
    if [ -z "$ALLOWED_NETWORKS" ]; then
        echo "[ZeroPath] ⚠ No access restrictions configured"
    fi
    echo ""
    
    exec /usr/local/bin/chisel client \
        --auth "$CHISEL_AUTH" \
        --tls-skip-verify \
        "$BROKER_SERVER" \
        R:0.0.0.0:1080:socks
fi
