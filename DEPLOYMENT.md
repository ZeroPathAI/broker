# Deploying the ZeroPath broker

How to deploy and configure the ZeroPath broker inside your network. The broker is a
single small Go daemon (a distroless container or a static binary). It makes **only
outbound connections** — no inbound firewall changes are required.

See [`README.md`](README.md) for the architecture and the full configuration reference.

## What you need from ZeroPath

Before starting, ZeroPath gives you:

- **Broker endpoint** — e.g. `broker.acme.zeropath.com:8443`
- **Enrollment URL** — e.g. `https://acme.zeropath.com/api/broker/enroll`
- **A one-time enrollment token** (valid ~30 minutes)
- **The agreed list of internal targets** you are authorizing ZeroPath to reach

The daemon obtains everything else it needs — its signed client certificate, the CA
chain used to trust the gateway, and the gateway's SPKI pin — automatically during
enrollment. None of that is handed over out of band.

## Prerequisites

- Outbound TCP `:8443` to the broker endpoint and outbound `:443` to the enrollment
  URL. No inbound rules.
- A place to run one container (Kubernetes, or a VM with Docker/systemd).
- Network reachability from the broker host to each internal target
  (e.g. `ghes.corp:443`).

## Step 1 — Get the image

Build from source (this repo):

```bash
docker build -t zeropath-broker .
```

The image is **distroless static**, `CGO_ENABLED=0`, runs as non-root uid `65532`, and
needs **no `NET_ADMIN`/`NET_RAW`** (only outbound connections + an unprivileged proxy
port). (ZeroPath can also publish a pre-built image to your registry.)

## Step 2 — Write the local allowlist

The reverse allowlist is **default-deny** and the effective allowlist is the
**intersection** of what ZeroPath authorizes (pushed over the control stream) and this
local file. Neither side can unilaterally widen reachability.

`allowlist.yaml`:

```yaml
version: 3
default: deny            # only "deny" is supported
targets:
  - host: ghes.corp
    port: 443
  - host: gitlab.internal
    port: 443
```

Mount it at `/etc/zeropath/allowlist.yaml` (or point `BROKER_ALLOWLIST_FILE` at it).

## Step 3 — Configure the environment

| Variable | Required | Default | Meaning |
|----------|----------|---------|---------|
| `ZEROPATH_BROKER_ENDPOINT` | yes | — | Gateway `host:8443` for the mTLS dial. |
| `ZEROPATH_ENROLL_URL` | first boot only | — | Enrollment endpoint (the `/api/broker/enroll` URL). |
| `ZEROPATH_ENROLL_TOKEN` | first boot only | — | The one-time enrollment token. |
| `BROKER_ALLOWLIST_FILE` | no | `/etc/zeropath/allowlist.yaml` | Local half of the intersection allowlist. |
| `BROKER_CERT_DIR` | no | `/var/lib/zeropath/certs` | Where the enrolled mTLS identity is stored (needs a writable, persistent mount). |
| `BROKER_FORWARD_PROXY_LISTEN` | no | `:3128` | Forward CONNECT proxy listen address. |

`BROKER_CERT_DIR` must be a **persistent** writable volume — it holds the enrolled key,
cert, CA chain, and SPKI pin. Losing it means re-enrolling.

## Step 4 — Deploy

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: zeropath-broker
spec:
  replicas: 1
  selector:
    matchLabels: { app: zeropath-broker }
  template:
    metadata:
      labels: { app: zeropath-broker }
    spec:
      automountServiceAccountToken: false
      containers:
        - name: broker
          image: zeropath-broker:latest
          env:
            - { name: ZEROPATH_BROKER_ENDPOINT, value: "broker.acme.zeropath.com:8443" }
            - { name: ZEROPATH_ENROLL_URL,      value: "https://acme.zeropath.com/api/broker/enroll" }
            - name: ZEROPATH_ENROLL_TOKEN
              valueFrom: { secretKeyRef: { name: zeropath-broker-enroll, key: token } }
          ports:
            - { name: forward-proxy, containerPort: 3128 }
          volumeMounts:
            - { name: certs,     mountPath: /var/lib/zeropath/certs }
            - { name: allowlist, mountPath: /etc/zeropath, readOnly: true }
          securityContext:
            runAsNonRoot: true
            runAsUser: 65532
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: { drop: [ALL] }
      volumes:
        - name: certs
          persistentVolumeClaim: { claimName: zeropath-broker-certs }
        - name: allowlist
          configMap: { name: zeropath-broker-allowlist }   # key: allowlist.yaml
```

Recommended: attach a **default-deny egress** NetworkPolicy that permits only DNS, the
broker endpoint `:8443`, the enrollment host `:443`, and your internal targets.

### systemd (VM)

```ini
[Unit]
Description=ZeroPath Broker
After=network-online.target

[Service]
ExecStart=/usr/local/bin/broker
Environment=ZEROPATH_BROKER_ENDPOINT=broker.acme.zeropath.com:8443
Environment=ZEROPATH_ENROLL_URL=https://acme.zeropath.com/api/broker/enroll
EnvironmentFile=/etc/zeropath/enroll.env        # holds ZEROPATH_ENROLL_TOKEN
Environment=BROKER_CERT_DIR=/var/lib/zeropath/certs
Environment=BROKER_ALLOWLIST_FILE=/etc/zeropath/allowlist.yaml
DynamicUser=yes
StateDirectory=zeropath/certs
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Step 5 — First-boot enrollment (automatic)

On first boot, with no stored identity and `ZEROPATH_ENROLL_TOKEN` +
`ZEROPATH_ENROLL_URL` set, the daemon:

1. generates an EC P-256 keypair locally (the private key never leaves the host),
2. sends a CSR to the enrollment URL over server-authenticated TLS,
3. receives a signed client certificate + CA chain + SPKI pin + bootstrap allowlist,
4. persists them to `BROKER_CERT_DIR` (`0600` files, `0700` dir), and
5. discards the one-time token.

After that it maintains one outbound mTLS + yamux connection to the gateway, with
automatic reconnect (capped exponential backoff). Subsequent boots reuse the stored
identity — the enrollment token is only needed once.

## Step 6 — (Optional) route ZeroPath API clients through the forward proxy

If you want your CLI / IDE / MCP traffic to ZeroPath to egress through the broker as a
single audited channel, point them at the daemon's forward proxy — the base URL stays
`zeropath.com`:

```bash
export HTTPS_PROXY=http://<broker-host>:3128
```

The forward proxy accepts **only** `CONNECT zeropath.com:443`; anything else is
refused. It splices raw TLS, so it never sees your API tokens.

## Verifying it works

- The daemon logs `tunnel: mTLS handshake OK ... (server SPKI pin verified)` once
  connected.
- In the ZeroPath UI/API the broker shows `ACTIVE` with a recent `lastConnectedAt`.
- Start a scan of an on-prem repo; it should clone without you having whitelisted any
  ZeroPath IP.

## Hardening checklist

- `runAsNonRoot` (uid 65532), `readOnlyRootFilesystem: true`, `capabilities.drop:
  [ALL]`, `automountServiceAccountToken: false`.
- No `NET_ADMIN`/`NET_RAW` — the broker never needs them.
- Persistent, writable mount only for `BROKER_CERT_DIR`.
- Default-deny egress; allow only DNS, the broker endpoint, the enrollment host, and
  your authorized targets.
- Keep `allowlist.yaml` as tight as possible — it is your independent veto over what
  ZeroPath can reach, even if the ZeroPath-side allowlist is broader.
