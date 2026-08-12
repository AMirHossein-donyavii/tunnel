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
	req := c.encode(nil, nil, nil, key, tunnel, 1, data, false)
	gd, gk, ok := c.parseServer(req, tunnel)
	if !ok || gk != key || !bytes.Equal(gd, data) {
		t.Fatalf("parseServer: ok=%v key=%d data=%q", ok, gk, gd)
	}

	// server -> dialer (reply)
	rep := c.encode(nil, nil, nil, key, tunnel, 2, data, true)
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
	seg := c.encode(nil, src, dst, key, tunnel, 1, data, false)
	gd, gk, ok := c.parseServer(seg, tunnel)
	if !ok || gk != key || !bytes.Equal(gd, data) {
		t.Fatalf("parseServer: ok=%v key=%d data=%q", ok, gk, gd)
	}
	// wrong tunnel port -> not for us
	if _, _, ok := c.parseServer(seg, 9999); ok {
		t.Fatal("parseServer should reject a wrong dst port")
	}

	// server -> dialer: srcPort=tunnel, dstPort=key
	rep := c.encode(nil, src, dst, key, tunnel, 2, data, true)
	gd, ok = c.matchClient(rep, key, tunnel)
	if !ok || !bytes.Equal(gd, data) {
		t.Fatalf("matchClient: ok=%v data=%q", ok, gd)
	}

	// A valid TCP checksum verifies to zero when recomputed over the segment.
	if got := tcpChecksum(src, dst, seg); got != 0 {
		t.Fatalf("tcp checksum should verify to 0, got %#04x", got)
	}
}

// The SPF icmp profile is built on echo messages, so it has the same exposure
// as the TUN icmp carrier: the listener's kernel answers echo requests by
// itself, and its reply repeats our payload with our echo id — which was
// everything this codec matched on. The dialer accepted that mirror as peer
// traffic, fed its own ciphertext to the handshake, and the profile carried
// nothing at all. It appeared to work only with net.ipv4.icmp_echo_ignore_all=1,
// which costs the server ping on every interface.
func TestSPFICMPRejectsTheKernelsMirroredRequest(t *testing.T) {
	c := icmpCodec{}
	const key = 4242
	frame := []byte("encrypted frame")

	// What the dialer put on the wire.
	req := c.encode(nil, nil, nil, key, 0, 1, frame, false)

	// The listener's kernel mirrors it back: same bytes, same id, but the type
	// flipped to Echo Reply. That is indistinguishable from a real reply by
	// address and id, so only the direction tag can reject it.
	mirrored := append([]byte(nil), req...)
	mirrored[0] = icmpTypeEchoReplyV4
	if _, _, ok := parseEchoMsg(mirrored, false, true); !ok {
		t.Fatal("the mirror no longer parses as a reply; the test has stopped exercising the case")
	}
	if got, ok := c.matchClient(mirrored, key, 0); ok {
		t.Fatalf("dialer accepted its own request mirrored back as %q — the link "+
			"carries no traffic and cycles forever", got)
	}

	// A genuine reply from the listener is still accepted, unchanged.
	rep := c.encode(nil, nil, nil, key, 0, 2, frame, true)
	got, ok := c.matchClient(rep, key, 0)
	if !ok || !bytes.Equal(got, frame) {
		t.Fatalf("genuine reply rejected or mistrimmed: %q ok=%v", got, ok)
	}
}

// And the listener must ignore ordinary ping traffic, which would otherwise
// open a flow per source and be offered to the handshake.
func TestSPFICMPListenerIgnoresOrdinaryPing(t *testing.T) {
	var ping []byte
	ping = appendEchoHeader(ping, false, false, 7, 1)
	ping = append(ping, []byte("abcdefgh")...) // a real ping's payload
	finishICMP(ping, false)

	if _, _, ok := (icmpCodec{}).parseServer(ping, 0); ok {
		t.Fatal("a plain ping was accepted as a tunnel frame")
	}
}
