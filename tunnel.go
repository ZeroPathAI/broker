package main

// tunnel.go brings up and runs the single outbound tunnel to the gateway.
//
// Flow:
//  1. mTLS-dial ZEROPATH_BROKER_ENDPOINT (host:8443) over TLS 1.3. The broker
//     presents its client cert; the gateway presents a server cert that we pin
//     by SPKI (in addition to normal chain + hostname verification). We NEVER
//     set InsecureSkipVerify.
//  2. Run a yamux session over that one TLS conn. yamux is peer-symmetric, so
//     although the BROKER dialed, the GATEWAY can still OpenStream() reverse
//     streams back to us.
//  3. Open the CONTROL stream (the first stream, broker-initiated). Send hello,
//     then a heartbeat every 20s; apply allowlist pushes as they arrive.
//  4. Concurrently accept gateway-opened REVERSE streams (see reverse.go) and
//     expose the live session to the forward proxy (see forward.go).

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

// brokerVersion is advertised in the control-stream hello message.
const brokerVersion = "1.0"

// inboundControl is the union of gateway->broker control messages. Today only
// the "allowlist" message carries payload fields beyond the type discriminator.
type inboundControl struct {
	Type    string   `json:"type"`
	Version int      `json:"version"`
	Targets []Target `json:"targets"`
}

// helloMessage and heartbeatMessage are the broker->gateway control messages.
// They are separate types so each is exactly the contract's shape — there is no
// way to accidentally send a malformed hybrid.
type helloMessage struct {
	Type          string `json:"type"`
	BrokerVersion string `json:"brokerVersion"`
}

type heartbeatMessage struct {
	Type string `json:"type"`
	TS   int64  `json:"ts"`
}

// spkiPin computes the "sha256/BASE64" pin of a certificate's
// SubjectPublicKeyInfo, matching the format the gateway hands us at enroll time.
func spkiPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256/" + base64.StdEncoding.EncodeToString(sum[:])
}

// makePinVerifier returns a tls.Config.VerifyPeerCertificate callback that
// enforces expectedPin on the server's leaf certificate.
//
// Because RootCAs is set to the enrolled CA chain and InsecureSkipVerify stays
// false, Go's standard chain + hostname verification ALSO runs. This callback
// is defense-in-depth pinning ON TOP OF, not instead of, that verification.
func makePinVerifier(expectedPin string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("gateway presented no certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse gateway leaf certificate: %w", err)
		}
		got := spkiPin(leaf)
		if subtle.ConstantTimeCompare([]byte(got), []byte(expectedPin)) != 1 {
			return fmt.Errorf("gateway SPKI pin mismatch: expected %q, got %q", expectedPin, got)
		}
		return nil
	}
}

// buildTLSConfig assembles the mTLS client config for the gateway dial.
func buildTLSConfig(id *brokerIdentity, serverName string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(id.clientCertPem, id.clientKeyPem)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(id.caChainPem) {
		return nil, fmt.Errorf("CA chain contained no valid certificates")
	}

	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{cert},
		RootCAs:               roots,
		ServerName:            serverName,
		InsecureSkipVerify:    false,
		VerifyPeerCertificate: makePinVerifier(id.serverSpkiPin),
	}, nil
}

// yamuxConfig returns the session config. Transport keepalives detect a dead
// gateway or an idle NAT timeout independently of the application heartbeats.
func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 30 * time.Second
	return c
}

// runTunnel dials the gateway, brings up yamux, opens the control stream, and
// blocks serving control traffic + reverse streams until the session dies. It
// returns an error so the caller (runTunnelLoop) can back off and redial.
func runTunnel(cfg Config, id *brokerIdentity, allow *Allowlist, fwd *forwardProxy) error {
	host, _, err := net.SplitHostPort(cfg.BrokerEndpoint)
	if err != nil {
		return fmt.Errorf("parse ZEROPATH_BROKER_ENDPOINT %q: %w", cfg.BrokerEndpoint, err)
	}

	tlsCfg, err := buildTLSConfig(id, host)
	if err != nil {
		return err
	}

	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", cfg.BrokerEndpoint, tlsCfg)
	if err != nil {
		return fmt.Errorf("mTLS dial gateway %q: %w", cfg.BrokerEndpoint, err)
	}
	defer conn.Close()
	log.Printf("tunnel: mTLS handshake OK to %s (server SPKI pin verified)", cfg.BrokerEndpoint)

	// yamux over the single TLS conn. The broker is the yamux CLIENT, but yamux
	// is symmetric so the gateway can still open reverse streams to us.
	session, err := yamux.Client(conn, yamuxConfig())
	if err != nil {
		return fmt.Errorf("start yamux client: %w", err)
	}
	defer session.Close()

	// The BROKER opens the FIRST stream as the control channel.
	control, err := session.OpenStream()
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}

	// Expose this live session to the forward proxy so CONNECT handlers can open
	// FWD streams, and detach it again when the session ends.
	fwd.setSession(session)
	defer fwd.clearSession()

	// Serve gateway-opened reverse streams in the background.
	go acceptReverseStreams(session, allow)

	// Block on the control loop; when it returns, the session is finished.
	return runControl(control, allow)
}

// runControl drives the control stream: it sends hello immediately, sends a
// heartbeat every 20s, and applies allowlist pushes received from the gateway.
// It returns when the stream read fails or a heartbeat write fails.
func runControl(control net.Conn, allow *Allowlist) error {
	if err := writeControl(control, helloMessage{Type: "hello", BrokerVersion: brokerVersion}); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	// Reader goroutine: newline-delimited JSON in from the gateway.
	readErr := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(control)
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				readErr <- err
				return
			}
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			var msg inboundControl
			if err := json.Unmarshal(line, &msg); err != nil {
				log.Printf("control: ignoring malformed message: %v", err)
				continue
			}
			switch msg.Type {
			case "allowlist":
				allow.SetGatewayTargets(msg.Version, msg.Targets)
				log.Printf("control: applied gateway allowlist version=%d targets=%d", msg.Version, len(msg.Targets))
			default:
				log.Printf("control: ignoring unknown message type %q", msg.Type)
			}
		}
	}()

	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case err := <-readErr:
			return fmt.Errorf("control stream closed: %w", err)
		case <-heartbeat.C:
			if err := writeControl(control, heartbeatMessage{Type: "heartbeat", TS: time.Now().Unix()}); err != nil {
				return fmt.Errorf("send heartbeat: %w", err)
			}
		}
	}
}

// writeControl marshals msg and writes it as one newline-delimited JSON record.
func writeControl(w io.Writer, msg any) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal control message: %w", err)
	}
	payload = append(payload, '\n')
	if _, err := w.Write(payload); err != nil {
		return err
	}
	return nil
}
