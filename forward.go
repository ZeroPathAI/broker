package main

// forward.go implements the broker's FORWARD path: an HTTP CONNECT proxy that
// lets customer clients egress to zeropath.com:443 THROUGH the tunnel.
//
// The proxy accepts ONLY "CONNECT zeropath.com:443". For each accepted CONNECT
// it opens a FWD data stream on the live yamux session, writes the framed
// header, replies "200 Connection Established", and splices the raw TLS bytes.
// The broker NEVER terminates TLS, so it never sees the customer's ZeroPath API
// tokens. Any other CONNECT target is answered 403.

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// The only egress target the forward proxy will ever tunnel.
const (
	forwardTargetHost = "zeropath.com"
	forwardTargetPort = 443
)

// forwardProxy is the CONNECT proxy. It holds the current yamux session, which
// is swapped in/out by the tunnel loop as the session connects and drops.
type forwardProxy struct {
	mu      sync.RWMutex
	session *yamux.Session
}

func newForwardProxy() *forwardProxy {
	return &forwardProxy{}
}

// setSession / clearSession are called by the tunnel loop as sessions come and
// go. currentSession returns the live session, or nil when no tunnel is up.
func (p *forwardProxy) setSession(s *yamux.Session) {
	p.mu.Lock()
	p.session = s
	p.mu.Unlock()
}

func (p *forwardProxy) clearSession() {
	p.mu.Lock()
	p.session = nil
	p.mu.Unlock()
}

func (p *forwardProxy) currentSession() *yamux.Session {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.session
}

// listenAndServe blocks accepting CONNECT clients on addr for the life of the
// process, independent of tunnel reconnects. It returns only on a fatal listen
// error.
func (p *forwardProxy) listenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen forward proxy on %q: %w", addr, err)
	}
	log.Printf("forward: CONNECT proxy listening on %s (only %s:%d permitted)", addr, forwardTargetHost, forwardTargetPort)

	for {
		client, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("forward proxy accept: %w", err)
		}
		go p.handleClient(client)
	}
}

// handleClient handles a single CONNECT client connection.
func (p *forwardProxy) handleClient(client net.Conn) {
	defer client.Close()

	// Bound how long we wait for the CONNECT request line + headers.
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(client)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("forward: unreadable request: %v", err)
		return
	}
	if req.Method != http.MethodConnect {
		writeProxyError(client, http.StatusMethodNotAllowed, "only the CONNECT method is supported")
		return
	}

	// For CONNECT, req.Host is the authority-form "host:port" target.
	if !isPermittedForwardTarget(req.Host) {
		log.Printf("forward: 403 CONNECT %s (only %s:%d permitted)", req.Host, forwardTargetHost, forwardTargetPort)
		writeProxyError(client, http.StatusForbidden, fmt.Sprintf("only %s:%d may be tunneled", forwardTargetHost, forwardTargetPort))
		return
	}

	session := p.currentSession()
	if session == nil {
		writeProxyError(client, http.StatusBadGateway, "broker tunnel is not connected")
		return
	}

	stream, err := session.OpenStream()
	if err != nil {
		log.Printf("forward: open FWD stream failed: %v", err)
		writeProxyError(client, http.StatusBadGateway, "failed to open tunnel stream")
		return
	}
	defer stream.Close()

	reqID := newReqID()

	// As the stream OPENER, the broker writes the framed header first.
	if err := writeHeader(stream, streamHeader{
		Dir:   "FWD",
		Host:  forwardTargetHost,
		Port:  forwardTargetPort,
		ReqID: reqID,
	}); err != nil {
		log.Printf("forward: write FWD header failed reqId=%s: %v", reqID, err)
		writeProxyError(client, http.StatusBadGateway, "failed to initialize tunnel stream")
		return
	}

	// Tell the client the tunnel is up, then hand off to a raw byte splice.
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		log.Printf("forward: write 200 failed reqId=%s: %v", reqID, err)
		return
	}
	_ = client.SetReadDeadline(time.Time{}) // long-lived from here on

	log.Printf("forward: OPEN %s:%d reqId=%s", forwardTargetHost, forwardTargetPort, reqID)
	// Reads come through the buffered reader so any bytes the client pipelined
	// after the CONNECT line (e.g. a TLS ClientHello) are not lost; writes and
	// close go straight to the socket.
	splice(stream, bufferedConn{Reader: reader, Conn: client})
	log.Printf("forward: CLOSE reqId=%s", reqID)
}

// isPermittedForwardTarget returns true only for exactly zeropath.com:443
// (case-insensitive host, trailing dot tolerated). Everything else is refused.
func isPermittedForwardTarget(authority string) bool {
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		return false
	}
	if canonicalHost(host) != forwardTargetHost {
		return false
	}
	return port == strconv.Itoa(forwardTargetPort)
}

// writeProxyError writes a minimal HTTP error response to a CONNECT client.
func writeProxyError(w io.Writer, status int, message string) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(message), message)
}

// newReqID returns a short random correlation id for log tracing.
func newReqID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand should never fail; fall back to a timestamp so we still
		// emit a usable, unique-ish id for logging (it is not security-bearing).
		return fmt.Sprintf("fwd-%d", time.Now().UnixNano())
	}
	return "fwd-" + hex.EncodeToString(buf[:])
}

// bufferedConn presents a bufio.Reader for reads while writing/closing the
// underlying socket, so bytes http.ReadRequest already buffered are not lost
// when splicing begins.
type bufferedConn struct {
	*bufio.Reader
	net.Conn
}

// Read disambiguates the two embedded Read methods in favor of the buffered
// reader (which drains its buffer before reading from the socket).
func (c bufferedConn) Read(p []byte) (int, error) { return c.Reader.Read(p) }
