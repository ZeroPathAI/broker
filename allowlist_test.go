package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalHost(t *testing.T) {
	cases := map[string]string{
		"GHE.Corp":     "ghe.corp",
		"ghe.corp.":    "ghe.corp",
		"  ghe.CORP  ": "ghe.corp",
		"Example.COM.": "example.com",
		"zeropath.com": "zeropath.com",
	}
	for in, want := range cases {
		if got := canonicalHost(in); got != want {
			t.Errorf("canonicalHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// newTestAllowlist builds an Allowlist with only the local half populated,
// bypassing the YAML file for the pure intersection-logic tests.
func newTestAllowlist(local []Target) *Allowlist {
	return &Allowlist{localTargets: toKeySet(local)}
}

func TestEffectiveAllowlistRequiresBothSets(t *testing.T) {
	a := newTestAllowlist([]Target{
		{Host: "ghe.corp", Port: 443},
		{Host: "gitlab.internal", Port: 443},
	})

	// Default-deny: nothing is allowed until the gateway pushes an allowlist.
	if a.IsHostPortAllowed("ghe.corp", 443) {
		t.Fatal("expected default-deny before the gateway pushes an allowlist")
	}

	// Gateway pushes a set that only partially overlaps the local file.
	a.SetGatewayTargets(7, []Target{
		{Host: "ghe.corp", Port: 443},
		{Host: "jira.internal", Port: 443},
	})

	if !a.IsHostPortAllowed("ghe.corp", 443) {
		t.Error("ghe.corp:443 is in both sets and must be allowed")
	}
	if a.IsHostPortAllowed("gitlab.internal", 443) {
		t.Error("gitlab.internal:443 is local-only and must be denied")
	}
	if a.IsHostPortAllowed("jira.internal", 443) {
		t.Error("jira.internal:443 is gateway-only and must be denied")
	}
	if a.IsHostPortAllowed("ghe.corp", 8443) {
		t.Error("ghe.corp:8443 has a non-allowed port and must be denied")
	}
	if a.IsHostPortAllowed("unknown.corp", 443) {
		t.Error("unknown.corp:443 is in neither set and must be denied")
	}
}

func TestEffectiveAllowlistCaseAndDotInsensitive(t *testing.T) {
	a := newTestAllowlist([]Target{{Host: "GHE.Corp", Port: 443}})
	a.SetGatewayTargets(1, []Target{{Host: "ghe.corp.", Port: 443}})

	if !a.IsHostPortAllowed("Ghe.CORP", 443) {
		t.Error("host match must be case-insensitive and trailing-dot-insensitive")
	}
}

func TestIPDenyReasonDenied(t *testing.T) {
	denied := []string{
		"127.0.0.1",       // loopback
		"::1",             // loopback (v6)
		"0.0.0.0",         // unspecified
		"224.0.0.1",       // multicast
		"169.254.1.1",     // link-local
		"169.254.169.254", // IMDS (also link-local)
		"fd00:ec2::254",   // AWS IMDS over IPv6 (explicit metadata entry)
		"100.64.0.1",      // CGNAT
		"100.127.255.254", // CGNAT (upper edge)
	}
	for _, s := range denied {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: could not parse %q", s)
		}
		if reason := ipDenyReason(ip); reason == "" {
			t.Errorf("ipDenyReason(%s) = allowed, want denied", s)
		}
	}
}

func TestIPDenyReasonAllowed(t *testing.T) {
	// RFC1918 hosts are the whole point of the broker (on-prem targets), and a
	// routable public IP is fine too. None of these should be denied.
	allowed := []string{
		"10.0.0.5",     // RFC1918
		"172.16.4.9",   // RFC1918
		"192.168.1.10", // RFC1918
		"203.0.113.7",  // public (TEST-NET-3)
	}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: could not parse %q", s)
		}
		if reason := ipDenyReason(ip); reason != "" {
			t.Errorf("ipDenyReason(%s) = denied (%s), want allowed", s, reason)
		}
	}
}

func TestLoadAllowlistFileYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.yaml")
	content := "" +
		"version: 3\n" +
		"default: deny\n" +
		"targets:\n" +
		"  - host: GHE.corp\n" +
		"    port: 443\n" +
		"  - host: gitlab.internal\n" +
		"    port: 443\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp allowlist: %v", err)
	}

	a, err := LoadAllowlistFile(path)
	if err != nil {
		t.Fatalf("LoadAllowlistFile: %v", err)
	}

	// Gateway pushes only ghe.corp -> intersection allows only ghe.corp.
	a.SetGatewayTargets(3, []Target{{Host: "ghe.corp", Port: 443}})
	if !a.IsHostPortAllowed("ghe.corp", 443) {
		t.Error("ghe.corp:443 should be allowed (local file + gateway, case-insensitive)")
	}
	if a.IsHostPortAllowed("gitlab.internal", 443) {
		t.Error("gitlab.internal:443 was not gateway-pushed and should be denied")
	}
}

func TestLoadAllowlistFileRejectsNonDenyDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.yaml")
	content := "version: 1\ndefault: allow\ntargets: []\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp allowlist: %v", err)
	}
	if _, err := LoadAllowlistFile(path); err == nil {
		t.Error("expected LoadAllowlistFile to reject default: allow, got nil error")
	}
}

func TestLoadAllowlistFileMissing(t *testing.T) {
	if _, err := LoadAllowlistFile(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Error("expected error for missing allowlist file, got nil")
	}
}
