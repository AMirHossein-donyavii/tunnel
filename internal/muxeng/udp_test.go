package muxeng

import (
	"bytes"
	"io"
	"net"
	"testing"
)

// A UDP protocol that receives two datagrams merged, or one split in half, is
// receiving corruption — OpenVPN drops such packets and renegotiates, which is
// what a "works then breaks" tunnel looks like from the outside. A mux stream is
// an ordered byte stream with no boundaries of its own, so the framing is the
// only thing preserving them.
func TestDatagramBoundariesSurviveTheStream(t *testing.T) {
	var wire bytes.Buffer
	scratch := make([]byte, 0, 64)

	sent := [][]byte{
		[]byte("a"),
		{},                              // an empty datagram is a real datagram
		bytes.Repeat([]byte("x"), 1400), // a full-MTU one
		[]byte("last"),
	}
	for _, p := range sent {
		if err := writeDatagram(&wire, &scratch, p); err != nil {
			t.Fatalf("write %q: %v", p, err)
		}
	}

	buf := make([]byte, udpMaxDatagram)
	for i, want := range sent {
		got, err := readDatagram(&wire, buf)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("datagram %d came back as %d bytes, want %d — boundaries were lost",
				i, len(got), len(want))
		}
	}
	if _, err := readDatagram(&wire, buf); err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Fatalf("stream had trailing bytes after the last datagram: %v", err)
	}
}

// The buffer is reused across datagrams, so a long one followed by a short one
// must not leave the long one's tail behind.
func TestReusedWriteBufferDoesNotLeakTheLastDatagram(t *testing.T) {
	var wire bytes.Buffer
	scratch := make([]byte, 0, 8)

	long := bytes.Repeat([]byte("L"), 900)
	short := []byte("short")
	for _, p := range [][]byte{long, short} {
		if err := writeDatagram(&wire, &scratch, p); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, udpMaxDatagram)
	if _, err := readDatagram(&wire, buf); err != nil {
		t.Fatal(err)
	}
	got, err := readDatagram(&wire, buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, short) {
		t.Fatalf("second datagram is %q (%d bytes), want %q", got, len(got), short)
	}
}

// A peer must not be able to make the receiver allocate by announcing a huge
// datagram, and must not be able to desynchronise it either.
func TestOversizedLengthIsRefused(t *testing.T) {
	wire := bytes.NewBuffer([]byte{0xff, 0xff}) // announces 65535 bytes
	small := make([]byte, 1500)
	if _, err := readDatagram(wire, small); err == nil {
		t.Fatal("a datagram larger than the read buffer was accepted")
	}
}

// The stream header tells the exit which protocol and port a stream is for. The
// TCP form must keep working exactly as before — it is on the wire between every
// existing pair of servers — and a UDP header must be unmistakable.
func TestStreamHeaderCarriesProtocolAndPort(t *testing.T) {
	t.Run("udp", func(t *testing.T) {
		isUDP, port, extra, ok := parseDest(udpDest(1194)) // OpenVPN's port
		if !ok || !isUDP || port != 1194 || len(extra) != 0 {
			t.Fatalf("udp header parsed as udp=%v port=%d extra=%d ok=%v", isUDP, port, len(extra), ok)
		}
	})

	t.Run("tcp unchanged", func(t *testing.T) {
		dest := []byte{0x01, 0xbb} // 443, no proxy protocol
		isUDP, port, extra, ok := parseDest(dest)
		if !ok || isUDP || port != 443 || len(extra) != 0 {
			t.Fatalf("tcp header parsed as udp=%v port=%d extra=%d ok=%v", isUDP, port, len(extra), ok)
		}
	})

	t.Run("tcp with proxy protocol", func(t *testing.T) {
		dest := append([]byte{0x01, 0xbb}, []byte("PROXY-BYTES")...)
		isUDP, port, extra, ok := parseDest(dest)
		if !ok || isUDP || port != 443 || string(extra) != "PROXY-BYTES" {
			t.Fatalf("the proxy-protocol preamble must survive: udp=%v port=%d extra=%q", isUDP, port, extra)
		}
	})

	t.Run("rejects a malformed header", func(t *testing.T) {
		for _, bad := range [][]byte{nil, {0x00}, {0x00, 0x00}, {0x00, 0x00, 0x09, 0x01, 0x02}} {
			if _, _, _, ok := parseDest(bad); ok {
				t.Fatalf("accepted a malformed header %v", bad)
			}
		}
	})
}

// End to end over a real pipe: what goes in as datagrams comes out as the same
// datagrams, in order, with their sizes intact.
func TestRelayRoundTripOverAPipe(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	sizes := []int{1, 100, 1400, 20, 65000}
	go func() {
		scratch := make([]byte, 0, 64)
		for _, n := range sizes {
			p := bytes.Repeat([]byte{byte(n)}, n)
			if err := writeDatagram(a, &scratch, p); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, udpMaxDatagram)
	for _, n := range sizes {
		got, err := readDatagram(b, buf)
		if err != nil {
			t.Fatalf("%d-byte datagram: %v", n, err)
		}
		if len(got) != n {
			t.Fatalf("got %d bytes, want %d", len(got), n)
		}
		for _, c := range got {
			if c != byte(n) {
				t.Fatalf("%d-byte datagram came back with wrong contents", n)
			}
		}
	}
}
