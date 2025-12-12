# ZeroPath Reverse Broker

Secure reverse proxy with TLS encryption and access control.  
© 2025 ZeroPath Corp. - zeropath.com

## Features
- ✅ **TLS Encrypted** - All traffic encrypted with TLS
- ✅ **Access Control** - Client-side network and port restrictions
- ✅ **Reverse Proxy** - Client connects outbound only
- ✅ **Flexible Modes** - Full proxy or specific port forwarding

## Requirements

- **Custom credential (`CHISEL_AUTH`)** – generate a unique value for each deployment (for example `export BROKER_AUTH="broker:$(openssl rand -base64 32)"`) and supply it to both the server and every client.
- **TLS trust material** – the server terminates TLS with a self-signed certificate. Persist or mount your own certificate/key pair in `/tmp/certs` so clients can trust the endpoint according to your organization’s policies.
- **`NET_ADMIN` capability for network policies** – required whenever you use `ALLOWED_NETWORKS` or `BLOCKED_PORTS`. Without it the client stops instead of falling back to an unrestricted proxy.

## Quick Start

### Generate Credential
```bash
export BROKER_AUTH="broker:$(openssl rand -base64 32)"
```
Use the same credential for the server container and every client you deploy.

### Build
```bash
docker build -f Dockerfile.server -t broker-server .
docker build -f Dockerfile.client -t broker-client .
```

### Run Server
```bash
docker run -d \
  --name broker-server \
  -p 8443:8443 \
  -p 1080:1080 \
  -e CHISEL_AUTH="$BROKER_AUTH" \
  broker-server
```

### Run Client (Multiple Modes)

#### Mode 1: Full Network Proxy (Unrestricted)
```bash
docker run -d \
  --name broker-client \
  -e BROKER_SERVER="your-server:8443" \
  -e CHISEL_AUTH="$BROKER_AUTH" \
  broker-client
```

#### Mode 2: Network/IP Restricted
```bash
# Supports both CIDR ranges and individual IPs
docker run -d \
  --name broker-client \
  --cap-add=NET_ADMIN \
  -e BROKER_SERVER="your-server:8443" \
  -e CHISEL_AUTH="$BROKER_AUTH" \
  -e ALLOWED_NETWORKS="192.168.1.0/24,10.0.0.0/16,10.0.137.151,172.16.5.22" \
  broker-client
```

#### Mode 3: Blocked Ports
```bash
# Block sensitive ports (SSH, RDP, SMB)
docker run -d \
  --name broker-client \
  --cap-add=NET_ADMIN \
  -e BROKER_SERVER="your-server:8443" \
  -e CHISEL_AUTH="$BROKER_AUTH" \
  -e BLOCKED_PORTS="22,3389,445" \
  broker-client
```

#### Mode 4: Specific Port Forwarding (Most Secure)
```bash
# Only forward specific services - no general proxy
docker run -d \
  --name broker-client \
  -e BROKER_SERVER="your-server:8443" \
  -e CHISEL_AUTH="$BROKER_AUTH" \
  -e BROKER_MODE="ports" \
  -e ALLOWED_TARGETS="8080:192.168.1.126:80,3306:192.168.1.100:3306" \
  broker-client
  
# This creates:
# server:8080 → 192.168.1.126:80
# server:3306 → 192.168.1.100:3306
```

## Client Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `BROKER_SERVER` | Server address (required) | `broker.example.com:8443` |
| `CHISEL_AUTH` | Authentication | `broker:$(openssl rand -base64 32)` |
| `BROKER_MODE` | `socks` or `ports` | `ports` |
| `ALLOWED_NETWORKS` | CIDR ranges and/or IPs (requires NET_ADMIN) | `192.168.1.0/24,10.0.0.50,172.16.0.0/12` |
| `BLOCKED_PORTS` | Block specific ports (requires NET_ADMIN) | `22,3389,445` |
| `ALLOWED_TARGETS` | Port forwards for `ports` mode | `8080:web:80,3306:db:3306` |

## ALLOWED_NETWORKS Format

The `ALLOWED_NETWORKS` variable accepts both CIDR notation and individual IP addresses:

```bash
# CIDR ranges
ALLOWED_NETWORKS="192.168.1.0/24,10.0.0.0/16,172.16.0.0/12"

# Individual IPs  
ALLOWED_NETWORKS="10.0.137.151,192.168.1.50,172.16.5.22"

# Mix of both
ALLOWED_NETWORKS="192.168.1.0/24,10.0.137.151,172.16.0.0/16,192.168.5.100"
```

## Interactive Test Script

The test script provides an interactive menu to test different restriction modes:

```bash
./test-client.sh

# You'll see:
# 1) Full network proxy (unrestricted)
# 2) Network/IP restricted proxy
# 3) Specific port forwarding only
# 4) Proxy with blocked ports
```
The script prompts for `BROKER_SERVER` and `CHISEL_AUTH` if they are not already set in your environment.

## Using the Proxy

**IMPORTANT: Always use `--max-time` with curl to prevent hanging!**

```bash
# After client connects (check first!)
docker exec broker-server netstat -tulpan | grep 1080

# Use as SOCKS5 proxy
curl --max-time 5 --proxy socks5://server:1080 https://httpbin.org/ip
curl --max-time 10 --proxy socks5://server:1080 http://192.168.1.100

# With proxychains4
echo "socks5 server 1080" >> /etc/proxychains4.conf
proxychains4 curl http://192.168.1.100
```

## Security Best Practices

### 1. Use Port Forwarding Mode (Most Secure)
Instead of full proxy, forward only needed services:
```bash
-e BROKER_MODE="ports" \
-e ALLOWED_TARGETS="8080:web.internal:80,3306:db.internal:3306"
```

### 2. Network Restrictions (Good)
Limit proxy to specific networks and IPs:
```bash
-e ALLOWED_NETWORKS="192.168.1.0/24,10.0.0.0/16,10.0.137.151"
```

### 3. Block Sensitive Ports (Minimum)
At minimum, block administrative ports:
```bash
-e BLOCKED_PORTS="22,3389,445,5900,5985,5986"
```

### 4. Firewall on Server
Even with strong credentials, restrict who can reach port 1080:
```bash
iptables -A INPUT -p tcp --dport 1080 -s YOUR_IP/32 -j ACCEPT
iptables -A INPUT -p tcp --dport 1080 -j DROP
```

### 5. TLS Certificates
Persist or mount your TLS material (key and certificate) into `/tmp/certs` so that clients can trust the server endpoint. Rotate these files according to your organization’s policies and distribute the public certificate alongside the broker credentials.

## Architecture

```
Client Restrictions:
[Client] → [Network Filter] → [Chisel Client] → TLS → [Server:8443]
             |
             ├─ ALLOWED_NETWORKS: CIDR ranges or individual IPs
             ├─ BLOCKED_PORTS: Block sensitive ports
             └─ ALLOWED_TARGETS: Only specific services

Server Side:
[Server:8443] → [Proxy:1080] (opens after client connects)
```

## Port 1080 Behavior

**Port 1080 only opens AFTER a client connects!**

```bash
# Before client connects
netstat -an | grep 1080  # Nothing

# After client connects  
netstat -an | grep 1080  # tcp 0.0.0.0:1080 LISTEN
```

## Troubleshooting

### Connection Hangs
Always use `--max-time`:
```bash
curl --max-time 10 --proxy socks5://server:1080 http://target
```

### Certificate Errors
Client automatically uses `--tls-skip-verify` for self-signed certs.

### Network Restrictions Not Working
Requires `--cap-add=NET_ADMIN` when running container.

### Check Client Connection
```bash
docker logs broker-server | grep session
docker exec broker-server netstat -tulpan | grep 1080
```

## Files
- `Dockerfile.server` - Server container
- `Dockerfile.client` - Client container  
- `server-entrypoint.sh` - Server script
- `client-entrypoint.sh` - Client script with access controls
- `test-client.sh` - Interactive test with restriction examples
- `deploy-example.sh` - Production deployment examples

---
© 2025 ZeroPath Corp. - zeropath.com
