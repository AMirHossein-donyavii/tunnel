package l3

import (
	"bytes"
	"net"
	"testing"
)

func TestICMPCodecRoundTrip(t *testing.T) {
	c := icmpCodec{}
	key, tunnel := 4444, 1234
	data := []byte("icmp-spf-payload")

	// dialer -> server (request)
	req, err := c.encode(nil, nil, key, tunnel, 1, data, false)
	if err != nil {
		t.Fatal(err)
	}
	gd, gk, ok := c.parseServer(req, tunnel)
	if !ok || gk != key || !bytes.Equal(gd, data) {
		t.Fatalf("parseServer: ok=%v key=%d data=%q", ok, gk, gd)
	}

	// server -> dialer (reply)
	rep, err := c.encode(nil, nil, key, tunnel, 2, data, true)
	if err != nil {
		t.Fatal(err)
	}
	gd, ok = c.matchClient(rep, key, tunnel)
	if !ok || !bytes.Equal(gd, data) {
		t.Fatalf("matchClient: ok=%v data=%q", ok, gd)
	}
	// wrong key must not match
	if _, ok := c.matchClient(rep, 9999, tunnel); ok {
		t.Fatal("matchClient should reject a mismatched id")
	}
}

func TestTCPCodecRoundTrip(t *testing.T) {
	c := tcpCodec{}
	src := net.ParseIP("5.34.222.4")
	dst := net.ParseIP("195.62.4.29")
	key, tunnel := 5555, 1234
	data := []byte("tcp-spf-payload-of-some-length")

	// dialer -> server: srcPort=key, dstPort=tunnel
	seg, _ := c.encode(src, dst, key, tunnel, 1, data, false)
	gd, gk, ok := c.parseServer(seg, tunnel)
	if !ok || gk != key || !bytes.Equal(gd, data) {
		t.Fatalf("parseServer: ok=%v key=%d data=%q", ok, gk, gd)
	}
	// wrong tunnel port -> not for us
	if _, _, ok := c.parseServer(seg, 9999); ok {
		t.Fatal("parseServer should reject a wrong dst port")
	}

	// server -> dialer: srcPort=tunnel, dstPort=key
	rep, _ := c.encode(src, dst, key, tunnel, 2, data, true)
	gd, ok = c.matchClient(rep, key, tunnel)
	if !ok || !bytes.Equal(gd, data) {
		t.Fatalf("matchClient: ok=%v data=%q", ok, gd)
	}

	// A valid TCP checksum verifies to zero when recomputed over the segment.
	if got := tcpChecksum(src, dst, seg); got != 0 {
		t.Fatalf("tcp checksum should verify to 0, got %#04x", got)
	}
}
