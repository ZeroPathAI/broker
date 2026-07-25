package main

// reverse.go services REVERSE ("REV") data streams: the gateway asking the
// broker to reach an on-prem LAN host on ZeroPath's behalf.
//
// The gateway OPENS the stream and writes the framed header first. The broker:
//  1. reads and validates the header (must be dir="REV"),
//  2. checks host:port against the effective (intersection) allowlist,
//  3. resolves + IP-screens the target (anti-rebinding),
//  4. dials the screened LAN address, and
//  5. splices raw bytes bidirectionally.
//
// If the target is not allowed, the broker writes NOTHING back and closes the
// stream — a denied reverse request is indistinguishable from a closed stream.

import (
	"io"
	"log"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

// acceptReverseStreams loops accepting gateway-opened streams and services each
// as a reverse data stream. On the broker side, AcceptStream only ever yields
// streams the GATEWAY opened (the broker-opened control stream never appears
// here), so every accepted stream is a REV stream.
func acceptReverseStreams(session *yamux.Session, allow *Allowlist) {
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			// Session closed or errored; the tunnel loop will redial.
			log.Printf("reverse: stopped accepting streams: %v", err)
			return
		}
		go handleReverseStream(stream, allow)
	}
}

// handleReverseStream services a single reverse stream end to end.
func handleReverseStream(stream *yamux.Stream, allow *Allowlist) {
	defer stream.Close()

	// Bound how long we wait for the opener's header so a stalled stream can't
	// pin a goroutine forever; clear the deadline before the long-lived splice.
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	hdr, err := readHeader(stream)
	if err != nil {
		log.Printf("reverse: bad stream header: %v", err)
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	if hdr.Dir != "REV" {
		log.Printf("reverse: refusing stream dir=%q (expected REV) reqId=%s", hdr.Dir, hdr.ReqID)
		return
	}

	// (a)+(b) intersection allowlist check on the requested host:port.
	if !allow.IsHostPortAllowed(hdr.Host, hdr.Port) {
		log.Printf("reverse: DENY host=%s port=%d reqId=%s (not in effective allowlist)", hdr.Host, hdr.Port, hdr.ReqID)
		return
	}

	// Anti-rebinding: resolve and screen every IP, then dial the screened
	// literal so DNS cannot swap the address out from under us.
	dialAddr, err := resolveAndScreen(hdr.Host, hdr.Port)
	if err != nil {
		log.Printf("reverse: DENY host=%s port=%d reqId=%s: %v", hdr.Host, hdr.Port, hdr.ReqID, err)
		return
	}

	target, err := net.DialTimeout("tcp", dialAddr, 15*time.Second)
	if err != nil {
		log.Printf("reverse: dial %s failed reqId=%s: %v", dialAddr, hdr.ReqID, err)
		return
	}
	defer target.Close()

	log.Printf("reverse: OPEN host=%s port=%d reqId=%s -> %s", hdr.Host, hdr.Port, hdr.ReqID, dialAddr)
	splice(stream, target)
	log.Printf("reverse: CLOSE reqId=%s", hdr.ReqID)
}

// splice copies bytes bidirectionally between a and b until either side ends,
// then tears both down. Closing the destination when one copy finishes unblocks
// the opposite copy, so a one-sided EOF cannot wedge the pair open forever.
//
// Shared by reverse (LAN target <-> stream) and forward (client <-> stream).
func splice(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	pipe := func(dst io.WriteCloser, src io.Reader) {
		_, _ = io.Copy(dst, src)
		_ = dst.Close()
		done <- struct{}{}
	}
	go pipe(a, b)
	go pipe(b, a)
	<-done
	<-done
}
