#!/bin/bash
# ZeroPath Broker - Production Deployment Examples
# © 2025 ZeroPath Corp. - zeropath.com

echo "========================================="
echo "     ZeroPath Broker Deployment"
echo "========================================="
echo "© 2025 ZeroPath Corp. - zeropath.com"
echo ""

if [ -z "${BROKER_SERVER:-}" ]; then
    echo -n "Enter broker server address (host:port): "
    read BROKER_SERVER
fi

if [ -z "$BROKER_SERVER" ]; then
    echo "ERROR: Broker server address is required." >&2
    exit 1
fi

if [ -z "${BROKER_AUTH:-}" ]; then
    echo -n "Enter CHISEL_AUTH credential (username:password): "
    read -r BROKER_AUTH
fi

if [ -z "$BROKER_AUTH" ]; then
    echo "ERROR: CHISEL_AUTH credential is required." >&2
    exit 1
fi

# Example 1: High Security - Specific Services Only
deploy_high_security() {
    echo "[ZeroPath] Deploying HIGH SECURITY configuration"
    echo "[ZeroPath] Only allowing specific service access:"
    echo "  • Web UI on port 8080"
    echo "  • Database on port 3306"
    echo ""
    
    docker run -d \
        --name broker-client-secure \
        --restart unless-stopped \
        -e BROKER_SERVER="${BROKER_SERVER}" \
        -e CHISEL_AUTH="${BROKER_AUTH}" \
        -e BROKER_MODE="ports" \
        -e ALLOWED_TARGETS="8080:webapp.internal:80,3306:database.internal:3306" \
        broker-client
        
    echo "[ZeroPath] ✓ Deployed - Only specified services accessible"
}

# Example 2: Medium Security - Network Restricted
deploy_medium_security() {
    echo "[ZeroPath] Deploying MEDIUM SECURITY configuration"
    echo "[ZeroPath] Network access restrictions:"
    echo "  • Internal networks and specific IPs only"
    echo "  • Blocked admin ports"
    echo ""
    
    docker run -d \
        --name broker-client-medium \
        --restart unless-stopped \
        --cap-add=NET_ADMIN \
        -e BROKER_SERVER="${BROKER_SERVER}" \
        -e CHISEL_AUTH="${BROKER_AUTH}" \
        -e BROKER_MODE="socks" \
        -e ALLOWED_NETWORKS="192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,10.0.137.151" \
        -e BLOCKED_PORTS="22,23,3389,445,5900,5985,5986" \
        broker-client
        
    echo "[ZeroPath] ✓ Deployed - Network restricted proxy"
}

# Example 3: Low Security - Full Access (NOT RECOMMENDED)
deploy_low_security() {
    echo "[ZeroPath] Deploying LOW SECURITY configuration"
    echo "[ZeroPath] ⚠ WARNING: Full network access enabled!"
    echo ""
    
    docker run -d \
        --name broker-client-full \
        --restart unless-stopped \
        -e BROKER_SERVER="${BROKER_SERVER}" \
        -e CHISEL_AUTH="${BROKER_AUTH}" \
        -e BROKER_MODE="socks" \
        broker-client
        
    echo "[ZeroPath] ⚠ Deployed - Full access (secure with server firewall!)"
}

# Example 4: Custom Configuration
deploy_custom() {
    echo "[ZeroPath] Custom deployment configuration:"
    echo ""
    echo "Enter server address (e.g., broker.example.com:8443):"
    read SERVER
    
    echo "Select security level:"
    echo "1) High - Specific ports only"
    echo "2) Medium - Network restricted proxy"
    echo "3) Low - Full proxy"
    read LEVEL
    
    case $LEVEL in
        1)
            echo "Enter port forwards (e.g., 8080:web:80,3306:db:3306):"
            read FORWARDS
            docker run -d \
                --name broker-client-custom \
                --restart unless-stopped \
                -e BROKER_SERVER="$SERVER" \
                -e CHISEL_AUTH="${BROKER_AUTH}" \
                -e BROKER_MODE="ports" \
                -e ALLOWED_TARGETS="$FORWARDS" \
                broker-client
            ;;
        2)
            echo "Enter allowed networks/IPs (e.g., 192.168.1.0/24,10.0.137.151):"
            read NETWORKS
            docker run -d \
                --name broker-client-custom \
                --restart unless-stopped \
                --cap-add=NET_ADMIN \
                -e BROKER_SERVER="$SERVER" \
                -e CHISEL_AUTH="${BROKER_AUTH}" \
                -e ALLOWED_NETWORKS="$NETWORKS" \
                -e BLOCKED_PORTS="22,3389,445" \
                broker-client
            ;;
        3)
            docker run -d \
                --name broker-client-custom \
                --restart unless-stopped \
                -e BROKER_SERVER="$SERVER" \
                -e CHISEL_AUTH="${BROKER_AUTH}" \
                broker-client
            ;;
    esac
    
    echo "[ZeroPath] ✓ Custom deployment complete"
}

# Menu
echo "Select deployment type:"
echo "1) High Security - Specific services only"
echo "2) Medium Security - Network restricted proxy"
echo "3) Low Security - Full proxy (not recommended)"
echo "4) Custom Configuration"
echo ""
echo -n "Choice [1-4]: "
read CHOICE

case $CHOICE in
    1) deploy_high_security ;;
    2) deploy_medium_security ;;
    3) deploy_low_security ;;
    4) deploy_custom ;;
    *) echo "[ZeroPath] Invalid choice"; exit 1 ;;
esac

echo ""
echo "[ZeroPath] Deployment complete!"
echo "[ZeroPath] Check status: docker logs broker-client-*"
echo "[ZeroPath] Stop: docker stop broker-client-*"
