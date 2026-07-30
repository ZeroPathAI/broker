package main

// allowlist.go implements the broker's default-deny target policy for REVERSE
// streams (the gateway asking the broker to dial an on-prem host).
//
// A target is allowed to be reverse-dialed IFF it is in BOTH:
//
//	(a) the gateway-pushed allowlist (received on the control stream), AND
//	(b) the local file BROKER_ALLOWLIST_FILE.
//
// i.e. the effective allowlist is the INTERSECTION of the two. Either side can
// only ever shrink what is reachable, never widen it. Before the gateway has
// pushed anything at all, nothing is allowed (default-deny).
//
// On top of the name-based intersection, the resolved IP of the target is
// re-screened (see ipDenyReason) so an allowlisted DNS name cannot be rebound
// to a loopback / metadata / link-local / CGNAT address.

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Target identifies a single host:port the broker may reverse-dial on the LAN.
type Target struct {
	Host string `yaml:"host" json:"host"`
	Port int    `yaml:"port" json:"port"`
}

// canonicalHost normalizes a hostname for case-insensitive, trailing-dot-
// insensitive comparison: "GHE.Corp." and "ghe.corp" compare equal.
func canonicalHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	return h
}

// key is the canonical map key for a target ("host:port", host normalized).
func (t Target) key() string {
	return fmt.Sprintf("%s:%d", canonicalHost(t.Host), t.Port)
}

// toKeySet turns a target slice into a set of canonical keys for O(1) lookup.
func toKeySet(targets []Target) map[string]struct{} {
	set := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		set[t.key()] = struct{}{}
	}
	return set
}

// allowlistFile mirrors the on-disk YAML shape:
//
//	version: 3
//	default: deny
//	targets:
//	  - host: ghe.corp
//	    port: 443
type allowlistFile struct {
	Version int      `yaml:"version"`
	Targets []Target `yaml:"targets"`
	Default string   `yaml:"default"`
}

// Allowlist holds the two halves of the intersection and answers allow/deny
// queries. It is safe for concurrent use: the gateway pushes updates on the
// control-stream goroutine while reverse-stream goroutines query it.
type Allowlist struct {
	mu sync.RWMutex

	// localTargets comes from BROKER_ALLOWLIST_FILE and is fixed for the life
	// of the process (reloading the file is out of scope for v1).
	localTargets map[string]struct{}

	// gatewayTargets is the most recent allowlist pushed on the control stream.
	// gatewaySet is false until the first push arrives, which keeps us in
	// default-deny during the brief window after connect.
	gatewayTargets map[string]struct{}
	gatewayVersion int
	gatewaySet     bool
}

// LoadAllowlistFile parses the local YAML allowlist. It refuses any default
// other than "deny": the contract only defines default-deny semantics, so a
// stray "allow" is treated as a misconfiguration rather than silently opening
// the broker up.
func LoadAllowlistFile(path string) (*Allowlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read allowlist file %q: %w", path, err)
	}

	var parsed allowlistFile
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parse allowlist file %q: %w", path, err)
	}
	if parsed.Default != "" && !strings.EqualFold(parsed.Default, "deny") {
		return nil, fmt.Errorf("allowlist file %q: unsupported default %q (only \"deny\" is supported)", path, parsed.Default)
	}

	return &Allowlist{
		localTargets: toKeySet(parsed.Targets),
	}, nil
}

// SetGatewayTargets replaces the gateway half of the intersection. Called each
// time the gateway pushes an {"type":"allowlist",...} control message.
func (a *Allowlist) SetGatewayTargets(version int, targets []Target) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gatewayTargets = toKeySet(targets)
	a.gatewayVersion = version
	a.gatewaySet = true
}

// IsHostPortAllowed reports whether host:port is in BOTH the local file and the
// gateway-pushed allowlist. This is the name-based half of the check; callers
// must ALSO screen the resolved IP via resolveAndScreen before dialing.
func (a *Allowlist) IsHostPortAllowed(host string, port int) bool {
	k := Target{Host: host, Port: port}.key()

	a.mu.RLock()
	defer a.mu.RUnlock()

	// Default-deny until the gateway has pushed at least one allowlist.
	if !a.gatewaySet {
		return false
	}
	if _, ok := a.localTargets[k]; !ok {
		return false
	}
	if _, ok := a.gatewayTargets[k]; !ok {
		return false
	}
	return true
}

// mustCIDR parses a CIDR constant at init time, panicking on a typo. Used only
// for compile-time-known constants below, so it can never fail at runtime.
func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(fmt.Sprintf("broker: invalid CIDR constant %q: %v", s, err))
	}
	return n
}

// cgnatNet is RFC 6598 shared (carrier-grade NAT) address space.
var cgnatNet = mustCIDR("100.64.0.0/10")

// metadataIPs are well-known cloud instance-metadata endpoints. An allowlisted
// DNS name that resolves to one of these is a rebinding attack aimed at stealing
// instance credentials, never a legitimate on-prem target.
var metadataIPs = []net.IP{
	net.ParseIP("169.254.169.254"), // AWS / GCP / Azure / OpenStack IMDS (also link-local)
	net.ParseIP("fd00:ec2::254"),   // AWS IMDS over IPv6 (unique-local, NOT link-local)
}

// ipDenyReason returns a non-empty human-readable reason when a resolved IP
// must NOT be dialed, or "" when the IP is acceptable.
//
// This is the anti-rebinding layer: even though the target HOSTNAME already
// passed the intersection allowlist, a compromised or malicious DNS answer
// could point that name at a dangerous address. We therefore refuse addresses
// a legitimate on-prem target would never live on:
//
//   - loopback (127.0.0.0/8, ::1)             -> pivot into broker-local services
//   - unspecified (0.0.0.0, ::)               -> nonsensical dial target
//   - multicast                               -> nonsensical dial target
//   - link-local (169.254.0.0/16, fe80::/10)  -> includes IMDS
//   - cloud metadata IPs                       -> credential theft (IMDS)
//   - CGNAT (100.64.0.0/10)                    -> carrier NAT, never on-prem
//
// RFC1918 private space (10/8, 172.16/12, 192.168/16) is intentionally NOT
// denied here: real on-prem GHES / GitLab / Jira hosts live on private IPs, and
// the hostname has already been EXPLICITLY allowlisted (both file + gateway),
// which is the "explicitly allowed" carve-out the contract calls for. Denying
// all RFC1918 would make the broker unable to reach any realistic target.
func ipDenyReason(ip net.IP) string {
	if ip == nil {
		return "unparseable address"
	}
	if ip.IsLoopback() {
		return "loopback address"
	}
	if ip.IsUnspecified() {
		return "unspecified address"
	}
	if ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return "multicast address"
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return "link-local address (169.254.0.0/16 or fe80::/10)"
	}
	for _, m := range metadataIPs {
		if m != nil && ip.Equal(m) {
			return "cloud metadata address"
		}
	}
	if cgnatNet.Contains(ip) {
		return "CGNAT address (100.64.0.0/10)"
	}
	return ""
}

// resolveAndScreen resolves host to IPs, screens EVERY resolved IP through
// ipDenyReason, and returns a dialable "ip:port" string built from the first
// screened IP.
//
// Two important properties:
//
//   - Fail closed: if ANY resolved IP is denied, the whole target is refused,
//     so an attacker cannot smuggle a bad IP in alongside a good one.
//   - No re-resolution race: we return a literal IP (not the hostname), so the
//     subsequent Dial connects to exactly the address we screened, closing the
//     DNS-rebinding TOCTOU window.
func resolveAndScreen(host string, port int) (string, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("resolve %q: no addresses returned", host)
	}
	for _, ip := range ips {
		if reason := ipDenyReason(ip); reason != "" {
			return "", fmt.Errorf("target %q resolves to a denied %s (%s)", host, reason, ip)
		}
	}
	return net.JoinHostPort(ips[0].String(), strconv.Itoa(port)), nil
}
