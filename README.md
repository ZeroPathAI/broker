# ZeroPath On-Prem Broker Daemon

The broker is a small Go daemon a customer runs **inside their own network**. It
lets ZeroPath SaaS reach private on-prem hosts (GitHub Enterprise Server, GitLab
self-managed, Bitbucket DC, Jira DC, internal registries) and lets customer
clients egress to `zeropath.com` — all over **one outbound TLS connection the
broker initiates**. No inbound firewall holes are required.

The broker is a **pure byte pipe**. It never terminates TLS to the internal
target or to `zeropath.com`, so it never sees repository contents, credentials,
or ZeroPath API tokens in cleartext.

## Architecture

```
                          one outbound mTLS+yamux conn
  ┌────────────────┐  ──────────────────────────────────▶  ┌──────────────┐
  │  on-prem       │                                        │  ZeroPath    │
  │  broker        │   CONTROL stream (broker-opened)       │  gateway     │
  │                │   • hello / heartbeat (broker→gw)      │  (:8443 mTLS)│
  │  ┌──────────┐  │   • allowlist push   (gw→broker)       │              │
  │  │ forward  │  │                                        │              │
  │  │ CONNECT  │  │   REV data streams (gateway-opened) ◀──┤              │
  │  │ proxy    │  │     broker dials LAN host, splices     │              │
  │  │ :3128    │  │   FWD data streams (broker-opened)  ───▶│ dials        │
  │  └──────────┘  │     gateway dials zeropath.com:443     │ zeropath.com │
  └───────┬────────┘                                        └──────────────┘
          │ dials                     splices raw TLS bytes; never decrypts
          ▼
   ghe.corp:443, gitlab.internal:443, ...  (LAN targets on the allowlist)
```

- **Transport**: TLS 1.3 with **mutual TLS**. The broker presents a client cert;
  the gateway's server cert is **pinned by SPKI** via a custom
  `VerifyPeerCertificate` (on top of normal chain + hostname verification).
  `InsecureSkipVerify` is never set anywhere.
- **Multiplexing**: [`hashicorp/yamux`](https://github.com/hashicorp/yamux) over
  the single TLS conn. yamux is peer-symmetric, which is what lets the
  **gateway** open **reverse** streams over the socket the **broker** dialed.

## Streams

| Stream    | Opened by | Purpose                                                        |
|-----------|-----------|----------------------------------------------------------------|
| CONTROL   | broker    | First stream. Newline-delimited JSON: `hello`, `heartbeat` (every 20s) out; `allowlist` pushes in. |
| REV (data)| gateway   | Reverse into the LAN. Broker checks the allowlist, dials `host:port`, splices. |
| FWD (data)| broker    | Forward out. One per customer-client CONNECT; gateway dials `zeropath.com:443`, splices. |

Every DATA stream begins with a length-prefixed JSON header
(`4-byte big-endian length` + JSON `{dir,host,port,reqId}`), then raw bytes.

## Effective allowlist (reverse direction)

Default-deny. A reverse target is allowed **iff it is in BOTH**:

1. the **gateway-pushed** allowlist (control stream), **and**
2. the **local file** `BROKER_ALLOWLIST_FILE`.

i.e. the effective allowlist is the **intersection** — either side can only
shrink reachability. Host matching is case-insensitive with a trailing dot
stripped.

On top of the name check, the **resolved IP** is re-screened so an allowlisted
name cannot be rebound to a dangerous address. The following are always refused:
loopback, unspecified, multicast, link-local (`169.254.0.0/16`, `fe80::/10`),
cloud metadata IPs (`169.254.169.254`, `fd00:ec2::254`), and CGNAT
(`100.64.0.0/10`). **RFC1918 private space is permitted** — real on-prem targets
live there and the hostname has already been explicitly allowlisted; that is the
"explicitly allowed" carve-out. Screening is fail-closed: if *any* resolved IP is
denied, the whole target is refused, and the broker dials the exact screened IP
literal (no re-resolution) to close the DNS-rebinding TOCTOU window.

## Forward proxy

The broker also runs an HTTP **CONNECT** proxy on `BROKER_FORWARD_PROXY_LISTEN`
(default `:3128`). It accepts **only** `CONNECT zeropath.com:443`; anything else
gets `403`. Each accepted CONNECT opens a FWD stream and splices the raw TLS
bytes — the broker never terminates TLS, so it never sees the customer's ZeroPath
API tokens.

## Enrollment (first boot)

When there is no identity on disk and `ZEROPATH_ENROLL_TOKEN` + `ZEROPATH_ENROLL_URL`
are set, the broker:

1. generates an **EC P-256** keypair locally (the private key never leaves the box),
2. builds a PKCS#10 CSR (empty subject — the server assigns identity),
3. `POST`s `{enrollmentToken, csrPem}` to `ZEROPATH_ENROLL_URL` over
   server-authenticated TLS 1.3,
4. receives `{clientCertPem, caChainPem, serverSpkiPin, allowlist}`,
5. persists the keypair + CA chain + SPKI pin to `BROKER_CERT_DIR` at `0600`
   (dir `0700`), and
6. discards the one-time token (it is only ever read from the environment).

On subsequent boots the stored identity is loaded and used to mTLS-dial the
gateway. The authoritative allowlist always arrives on the control stream; the
enrollment-response allowlist is an informational bootstrap.

## Configuration (environment)

| Variable                      | Required            | Default                          | Meaning |
|-------------------------------|---------------------|----------------------------------|---------|
| `ZEROPATH_BROKER_ENDPOINT`    | yes                 | —                                | Gateway `host:8443` for the mTLS dial. |
| `ZEROPATH_ENROLL_URL`         | first boot only     | —                                | Enrollment endpoint. |
| `ZEROPATH_ENROLL_TOKEN`       | first boot only     | —                                | One-time enrollment token. |
| `BROKER_ALLOWLIST_FILE`       | no                  | `/etc/zeropath/allowlist.yaml`   | Local half of the intersection allowlist. |
| `BROKER_CERT_DIR`             | no                  | `/var/lib/zeropath/certs`        | Where the mTLS identity is stored. |
| `BROKER_FORWARD_PROXY_LISTEN` | no                  | `:3128`                          | CONNECT proxy listen address. |

### `BROKER_ALLOWLIST_FILE` format

```yaml
version: 3
default: deny          # only "deny" is supported; any other value is rejected
targets:
  - host: ghe.corp
    port: 443
  - host: gitlab.internal
    port: 443
```

## Build, vet, test

There is **no vendored `go.sum`** committed here (the build environment has no Go
toolchain to generate module checksums). CI / the Docker build populate it via
`go mod download`. Run:

```bash
go mod download          # creates go.sum from go.mod
go build ./...
go vet ./...
go test ./...
```

## Container

```bash
docker build -t zeropath-broker .
```

The image is **distroless static**, built with `CGO_ENABLED=0`, and runs as the
non-root user **65532**. The broker requires **no `NET_ADMIN`/`NET_RAW`**: it only
makes outbound connections and binds an unprivileged port. Recommended runtime
hardening: `readOnlyRootFilesystem: true`, `runAsNonRoot: true`,
`capabilities.drop: [ALL]`, with a writable mount only for `BROKER_CERT_DIR`.
