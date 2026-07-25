package main

// enroll.go implements first-boot enrollment and on-disk identity management.
//
// On first boot the broker has no client certificate. It:
//  1. generates an EC P-256 keypair LOCALLY (the private key never leaves the
//     box),
//  2. builds a PKCS#10 CSR (leaving the subject blank — the server assigns the
//     real identity),
//  3. POSTs {enrollmentToken, csrPem} to ZEROPATH_ENROLL_URL over ordinary
//     server-authenticated TLS 1.3,
//  4. receives {clientCertPem, caChainPem, serverSpkiPin, allowlist},
//  5. persists the keypair + CA chain + SPKI pin to BROKER_CERT_DIR at 0600,
//  6. discards the one-time enrollment token.
//
// In steady state the stored identity is loaded and used for the mTLS dial to
// the gateway (see tunnel.go).

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// File names under BROKER_CERT_DIR that together make up the broker identity.
const (
	clientKeyFile  = "client.key.pem"
	clientCertFile = "client.crt.pem"
	caChainFile    = "ca-chain.pem"
	spkiPinFile    = "server-spki.pin"
)

// brokerIdentity is everything the steady-state tunnel needs: the client mTLS
// keypair, the CA chain that signs the gateway's server cert, and the pinned
// server SubjectPublicKeyInfo hash ("sha256/BASE64").
type brokerIdentity struct {
	clientCertPem []byte
	clientKeyPem  []byte
	caChainPem    []byte
	serverSpkiPin string
}

// enrollRequest / enrollResponse are the enrollment API's wire shapes.
type enrollRequest struct {
	EnrollmentToken string `json:"enrollmentToken"`
	CSRPem          string `json:"csrPem"`
}

type enrollResponse struct {
	ClientCertPem string   `json:"clientCertPem"`
	CAChainPem    string   `json:"caChainPem"`
	ServerSpkiPin string   `json:"serverSpkiPin"`
	Allowlist     []Target `json:"allowlist"`
}

// identityExists reports whether a complete identity is already present on disk.
func identityExists(certDir string) bool {
	for _, name := range []string{clientKeyFile, clientCertFile, caChainFile, spkiPinFile} {
		if _, err := os.Stat(filepath.Join(certDir, name)); err != nil {
			return false
		}
	}
	return true
}

// loadIdentity reads a previously-persisted identity from disk.
func loadIdentity(certDir string) (*brokerIdentity, error) {
	read := func(name string) ([]byte, error) {
		p := filepath.Join(certDir, name)
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %q: %w", p, err)
		}
		return b, nil
	}

	keyPem, err := read(clientKeyFile)
	if err != nil {
		return nil, err
	}
	certPem, err := read(clientCertFile)
	if err != nil {
		return nil, err
	}
	caPem, err := read(caChainFile)
	if err != nil {
		return nil, err
	}
	pinBytes, err := read(spkiPinFile)
	if err != nil {
		return nil, err
	}
	pin := strings.TrimSpace(string(pinBytes))
	if pin == "" {
		return nil, fmt.Errorf("stored SPKI pin at %q is empty", filepath.Join(certDir, spkiPinFile))
	}

	return &brokerIdentity{
		clientCertPem: certPem,
		clientKeyPem:  keyPem,
		caChainPem:    caPem,
		serverSpkiPin: pin,
	}, nil
}

// generateKeyAndCSR creates a fresh P-256 private key and a PEM-encoded PKCS#10
// CSR. The subject is intentionally empty: the enrollment server is the
// authority for broker identity and sets it on the issued certificate.
func generateKeyAndCSR() (keyPem []byte, csrPem []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate P-256 key: %w", err)
	}

	keyDer, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}
	keyPem = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDer})

	tmpl := x509.CertificateRequest{
		Subject:            pkix.Name{}, // server assigns identity
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDer})

	return keyPem, csrPem, nil
}

// doEnroll performs the enrollment HTTP exchange and returns the resulting
// identity. Enrollment runs over ordinary server-authenticated TLS 1.3 against
// the public ZeroPath control plane (WebPKI). Verification is NEVER disabled;
// the gateway's own server cert is separately SPKI-pinned in steady state.
func doEnroll(enrollURL, token string) (*brokerIdentity, error) {
	keyPem, csrPem, err := generateKeyAndCSR()
	if err != nil {
		return nil, err
	}

	reqBody, err := json.Marshal(enrollRequest{EnrollmentToken: token, CSRPem: string(csrPem)})
	if err != nil {
		return nil, fmt.Errorf("marshal enroll request: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: false,
			},
		},
	}

	httpReq, err := http.NewRequest(http.MethodPost, enrollURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("build enroll request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("POST enroll %q: %w", enrollURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("enroll returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var er enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return nil, fmt.Errorf("decode enroll response: %w", err)
	}
	if er.ClientCertPem == "" || er.CAChainPem == "" || er.ServerSpkiPin == "" {
		return nil, fmt.Errorf("enroll response missing required fields (clientCertPem/caChainPem/serverSpkiPin)")
	}

	log.Printf("enroll: received client certificate and %d bootstrap allowlist target(s)", len(er.Allowlist))

	return &brokerIdentity{
		clientCertPem: []byte(er.ClientCertPem),
		clientKeyPem:  keyPem,
		caChainPem:    []byte(er.CAChainPem),
		serverSpkiPin: er.ServerSpkiPin,
	}, nil
}

// persistIdentity writes the enrolled identity to certDir with tight perms.
// The private key and client cert are secret; the CA chain and pin are not, but
// there is no reason to widen their perms, so everything is 0600 in a 0700 dir.
func persistIdentity(certDir string, id *brokerIdentity) error {
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return fmt.Errorf("create cert dir %q: %w", certDir, err)
	}

	files := []struct {
		name string
		data []byte
	}{
		{clientKeyFile, id.clientKeyPem},
		{clientCertFile, id.clientCertPem},
		{caChainFile, id.caChainPem},
		{spkiPinFile, []byte(id.serverSpkiPin + "\n")},
	}
	for _, f := range files {
		p := filepath.Join(certDir, f.name)
		if err := os.WriteFile(p, f.data, 0o600); err != nil {
			return fmt.Errorf("write %q: %w", p, err)
		}
	}
	return nil
}

// enrollAndPersist runs the full first-boot flow: enroll, then persist. The
// enrollment token lives only in the environment and is never written to disk,
// so it is effectively discarded once this returns.
func enrollAndPersist(cfg Config) (*brokerIdentity, error) {
	id, err := doEnroll(cfg.EnrollURL, cfg.EnrollToken)
	if err != nil {
		return nil, err
	}
	if err := persistIdentity(cfg.CertDir, id); err != nil {
		return nil, err
	}
	return id, nil
}
