package main

// main.go wires the broker together: read config, obtain an mTLS identity
// (enrolling on first boot), start the forward CONNECT proxy, and keep a single
// tunnel to the gateway alive with reconnect backoff.
//
// See the ZeroPath Broker System Contract for the authoritative behavior; each
// source file's header comment maps to the relevant contract section.

import (
	"fmt"
	"log"
	"os"
	"time"
)

// Config is the fully-resolved broker configuration. Every field is populated
// by loadConfig (with documented defaults), so downstream code never has to
// re-check for "maybe unset" configuration.
type Config struct {
	EnrollURL          string // ZEROPATH_ENROLL_URL       (first boot only)
	EnrollToken        string // ZEROPATH_ENROLL_TOKEN     (first boot only)
	BrokerEndpoint     string // ZEROPATH_BROKER_ENDPOINT  (gateway host:8443)
	AllowlistFile      string // BROKER_ALLOWLIST_FILE
	CertDir            string // BROKER_CERT_DIR
	ForwardProxyListen string // BROKER_FORWARD_PROXY_LISTEN
}

// envOr returns the environment value for key, or def when it is unset/empty.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// loadConfig reads configuration from the environment and applies defaults.
// ZEROPATH_BROKER_ENDPOINT is always required. Enrollment-specific vars are
// validated later, only if a first boot is actually needed.
func loadConfig() (Config, error) {
	cfg := Config{
		EnrollURL:          os.Getenv("ZEROPATH_ENROLL_URL"),
		EnrollToken:        os.Getenv("ZEROPATH_ENROLL_TOKEN"),
		BrokerEndpoint:     os.Getenv("ZEROPATH_BROKER_ENDPOINT"),
		AllowlistFile:      envOr("BROKER_ALLOWLIST_FILE", "/etc/zeropath/allowlist.yaml"),
		CertDir:            envOr("BROKER_CERT_DIR", "/var/lib/zeropath/certs"),
		ForwardProxyListen: envOr("BROKER_FORWARD_PROXY_LISTEN", ":3128"),
	}
	if cfg.BrokerEndpoint == "" {
		return Config{}, fmt.Errorf("ZEROPATH_BROKER_ENDPOINT is required (gateway host:8443)")
	}
	return cfg, nil
}

// obtainIdentity returns the broker's mTLS identity, enrolling on first boot.
//
// First boot = no identity on disk AND an enrollment token/URL configured. If
// an identity already exists we always use it (ignoring any leftover token). If
// there is neither an identity nor enrollment config, we cannot proceed.
func obtainIdentity(cfg Config) (*brokerIdentity, error) {
	if identityExists(cfg.CertDir) {
		log.Printf("identity: using stored certificate in %s", cfg.CertDir)
		return loadIdentity(cfg.CertDir)
	}
	if cfg.EnrollToken == "" || cfg.EnrollURL == "" {
		return nil, fmt.Errorf("no stored identity in %s and enrollment not configured "+
			"(set ZEROPATH_ENROLL_URL and ZEROPATH_ENROLL_TOKEN for first boot)", cfg.CertDir)
	}
	log.Printf("identity: first boot, enrolling at %s", cfg.EnrollURL)
	id, err := enrollAndPersist(cfg)
	if err != nil {
		return nil, fmt.Errorf("enrollment failed: %w", err)
	}
	log.Printf("identity: enrollment complete, certificate stored in %s", cfg.CertDir)
	return id, nil
}

// runTunnelLoop keeps exactly one tunnel session alive, reconnecting with
// capped exponential backoff whenever it drops. It never returns under normal
// operation.
func runTunnelLoop(cfg Config, id *brokerIdentity, allow *Allowlist, fwd *forwardProxy) {
	const (
		minBackoff = 1 * time.Second
		maxBackoff = 30 * time.Second
	)
	backoff := minBackoff
	for {
		start := time.Now()
		if err := runTunnel(cfg, id, allow, fwd); err != nil {
			log.Printf("tunnel: disconnected: %v", err)
		} else {
			log.Printf("tunnel: session ended")
		}

		// A session that stayed up a while is healthy; reset the backoff.
		if time.Since(start) > time.Minute {
			backoff = minBackoff
		}
		log.Printf("tunnel: reconnecting in %s", backoff)
		time.Sleep(backoff)
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// Load the local allowlist up front: a missing/invalid file is a
	// misconfiguration we want surfaced immediately (default-deny would
	// otherwise silently block everything and hide the cause).
	allow, err := LoadAllowlistFile(cfg.AllowlistFile)
	if err != nil {
		return err
	}

	id, err := obtainIdentity(cfg)
	if err != nil {
		return err
	}

	// The forward CONNECT proxy runs for the life of the process and serves
	// 502 while no tunnel is up. A listen failure is fatal.
	fwd := newForwardProxy()
	go func() {
		if err := fwd.listenAndServe(cfg.ForwardProxyListen); err != nil {
			log.Fatalf("forward proxy stopped: %v", err)
		}
	}()

	// Steady state: never returns.
	runTunnelLoop(cfg, id, allow, fwd)
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetPrefix("zeropath-broker ")

	if err := run(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}
