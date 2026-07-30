package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestHeaderRoundTrip(t *testing.T) {
	want := streamHeader{Dir: "REV", Host: "ghe.corp", Port: 443, ReqID: "abc-123"}

	var buf bytes.Buffer
	if err := writeHeader(&buf, want); err != nil {
		t.Fatalf("writeHeader: %v", err)
	}
	got, err := readHeader(&buf)
	if err != nil {
		t.Fatalf("readHeader: %v", err)
	}
	if got != want {
		t.Errorf("round trip mismatch: got %+v, want %+v", got, want)
	}
}

func TestWriteHeaderFramesBigEndianLength(t *testing.T) {
	// Assert the exact framing the contract mandates: a 4-byte big-endian
	// length prefix whose value equals the JSON payload length.
	var buf bytes.Buffer
	if err := writeHeader(&buf, streamHeader{Dir: "FWD", Host: "zeropath.com", Port: 443, ReqID: "x"}); err != nil {
		t.Fatalf("writeHeader: %v", err)
	}
	raw := buf.Bytes()
	if len(raw) < 4 {
		t.Fatalf("frame too short: %d bytes", len(raw))
	}
	declared := binary.BigEndian.Uint32(raw[:4])
	if int(declared) != len(raw)-4 {
		t.Errorf("declared length %d != actual payload length %d", declared, len(raw)-4)
	}
}

func TestReadHeaderRejectsZeroLength(t *testing.T) {
	var buf bytes.Buffer
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 0)
	buf.Write(lenBuf[:])
	if _, err := readHeader(&buf); err == nil {
		t.Error("expected error on zero-length header, got nil")
	}
}

func TestReadHeaderRejectsOversizeLength(t *testing.T) {
	var buf bytes.Buffer
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], maxHeaderLen+1)
	buf.Write(lenBuf[:])
	if _, err := readHeader(&buf); err == nil {
		t.Error("expected error on oversize header length, got nil")
	}
}

func TestReadHeaderRejectsTruncatedPayload(t *testing.T) {
	// Claims 10 payload bytes but supplies only 3.
	var buf bytes.Buffer
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 10)
	buf.Write(lenBuf[:])
	buf.WriteString("abc")
	if _, err := readHeader(&buf); err == nil {
		t.Error("expected error on truncated header payload, got nil")
	}
}

func TestReadHeaderRejectsShortLengthPrefix(t *testing.T) {
	// Only 2 of the 4 length-prefix bytes are present.
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x01})
	if _, err := readHeader(&buf); err == nil {
		t.Error("expected error on short length prefix, got nil")
	}
}

func TestReadHeaderRejectsInvalidJSON(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("this is not json")
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	buf.Write(lenBuf[:])
	buf.Write(payload)
	if _, err := readHeader(&buf); err == nil {
		t.Error("expected error on invalid JSON payload, got nil")
	}
}
