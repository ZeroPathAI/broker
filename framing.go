package main

// framing.go implements the tiny wire format that prefixes every DATA stream.
//
// Per the ZeroPath Broker System Contract, whichever side OPENS a data stream
// writes a header first, framed as:
//
//	[ 4-byte big-endian uint32 length ][ that many bytes of JSON ]
//
// After the header, the stream carries raw opaque bytes that are spliced
// bidirectionally. The broker never parses those bytes — it is a pure pipe.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// streamHeader is the JSON object that opens every DATA stream.
//
//   - Dir is "REV" (gateway-opened, reverse into the LAN) or "FWD"
//     (broker-opened, forward out to zeropath.com).
//   - Host/Port name the intended target of the stream.
//   - ReqID is an opaque correlation id used only for logging/tracing.
type streamHeader struct {
	Dir   string `json:"dir"`
	Host  string `json:"host"`
	Port  int    `json:"port"`
	ReqID string `json:"reqId"`
}

// maxHeaderLen caps the framed header size. A legitimate header is a few dozen
// bytes; anything larger is a bug or an attempt to make us allocate wildly, so
// we refuse it rather than trust the length prefix blindly.
const maxHeaderLen = 64 * 1024

// writeHeader marshals h and writes it as a length-prefixed frame to w.
func writeHeader(w io.Writer, h streamHeader) error {
	payload, err := json.Marshal(h)
	if err != nil {
		return fmt.Errorf("marshal stream header: %w", err)
	}
	if len(payload) > maxHeaderLen {
		return fmt.Errorf("stream header too large: %d bytes (max %d)", len(payload), maxHeaderLen)
	}

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write header length prefix: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write header payload: %w", err)
	}
	return nil
}

// readHeader reads a single length-prefixed frame from r and unmarshals it.
//
// It fails closed on a zero, oversize, or truncated frame so a malformed header
// can never be mistaken for a valid target.
func readHeader(r io.Reader) (streamHeader, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return streamHeader{}, fmt.Errorf("read header length prefix: %w", err)
	}

	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 {
		return streamHeader{}, fmt.Errorf("empty stream header")
	}
	if n > maxHeaderLen {
		return streamHeader{}, fmt.Errorf("stream header too large: %d bytes (max %d)", n, maxHeaderLen)
	}

	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return streamHeader{}, fmt.Errorf("read header payload (%d bytes): %w", n, err)
	}

	var h streamHeader
	if err := json.Unmarshal(payload, &h); err != nil {
		return streamHeader{}, fmt.Errorf("unmarshal stream header: %w", err)
	}
	return h, nil
}
