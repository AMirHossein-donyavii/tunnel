package muxeng

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
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

// A mux stream blocks its writer once the peer's window is full. Writing to it
// straight from the socket loop meant that when the carrier congested the loop
// stopped reading — so every client on that port stalled behind whichever one
// was blocked, and the kernel's receive queue overflowed and discarded all of
// it. One slow peer took the whole forward down with it.
//
// Offering must therefore never block, whatever the carrier is doing.
func TestOfferNeverBlocksWhenTheCarrierStalls(t *testing.T) {
	s := &udpSession{out: make(chan dgram, 4)} // nothing draining it: a stalled carrier
	p := bytes.Repeat([]byte("x"), 1400)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			s.offer(p)
		}
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("offering blocked while the carrier was stalled — the socket loop " +
			"would stop reading and every client on this port would stall with it")
	}
	if got := s.dropped.Load(); got == 0 {
		t.Fatal("nothing was recorded as dropped, so the queue silently grew without bound")
	}
	if got := len(s.out); got > 4 {
		t.Fatalf("queue holds %d datagrams, past its depth of 4", got)
	}
}

// A datagram that has waited too long is worthless: the inner transport has
// already decided it was lost and sent another, so delivering it now is a
// duplicate that costs bandwidth and helps nobody. The UDP path this replaces
// would simply have dropped it.
func TestStaleDatagramsAreDroppedRatherThanSentLate(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	s := &udpSession{out: make(chan dgram, 8), closed: make(chan struct{})}
	// Queue one datagram that is already past its shelf life, then a fresh one.
	s.out <- dgram{b: takeDgram([]byte("stale")), enq: time.Now().Add(-2 * udpStale)}
	s.out <- dgram{b: takeDgram([]byte("fresh")), enq: time.Now()}
	close(s.out)

	// pump writes to the stream; substitute the pipe for it.
	go func() {
		scratch := make([]byte, 0, 64)
		for d := range s.out {
			if time.Since(d.enq) > udpStale {
				s.dropped.Add(1)
				giveDgram(d.b)
				continue
			}
			_ = writeDatagram(a, &scratch, d.b)
			giveDgram(d.b)
		}
		a.Close()
	}()

	buf := make([]byte, udpMaxDatagram)
	got, err := readDatagram(b, buf)
	if err != nil {
		t.Fatalf("the fresh datagram never arrived: %v", err)
	}
	if string(got) != "fresh" {
		t.Fatalf("got %q — a stale datagram was delivered late instead of dropped", got)
	}
	if s.dropped.Load() != 1 {
		t.Fatalf("dropped %d, want 1 (the stale one)", s.dropped.Load())
	}
}

// Buffers are recycled, so a short datagram must never inherit a long one's tail.
func TestRecycledDatagramBuffersDoNotLeakContents(t *testing.T) {
	long := takeDgram(bytes.Repeat([]byte("L"), 1400))
	giveDgram(long)
	short := takeDgram([]byte("hi"))
	if string(short) != "hi" {
		t.Fatalf("recycled buffer came back as %q, want %q", short, "hi")
	}
	giveDgram(short)
}

// The socket read loop offers datagrams while a session may be torn down by the
// reaper, by a stream error, or by the return pump ending.
//
// Teardown used to close the queue. A send on a closed channel panics, so the
// tunnel carried traffic normally until the FIRST session ended — an idle
// client, one stream error — and then the process died, taking every other
// tunnel on that server with it and not coming back. "Passed some data, then
// dropped completely and never reconnected" is exactly what that looks like.
//
// A session now ends by signalling, and the queue is never closed.
func TestOfferDuringTeardownDoesNotPanic(t *testing.T) {
	for i := 0; i < 200; i++ {
		s := &udpSession{out: make(chan dgram, 4), closed: make(chan struct{})}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				s.offer([]byte("datagram"))
			}
		}()
		go func() {
			defer wg.Done()
			time.Sleep(time.Microsecond)
			s.shutdown()
		}()
		wg.Wait()
	}
}

// Shutting a session down twice — the reaper and the pump can both decide it is
// over — must be harmless.
func TestShutdownIsIdempotent(t *testing.T) {
	s := &udpSession{out: make(chan dgram, 1), closed: make(chan struct{})}
	s.shutdown()
	s.shutdown()
	s.offer([]byte("after close")) // must not panic or block
}

// Opening a carrier stream waits for a live session, and while the carrier is
// down or reconnecting that wait runs to seconds. It used to happen inside the
// socket read loop, so a hiccup under load stopped the port being read for
// exactly as long — every client's traffic discarded by the kernel meanwhile,
// which a VPN reads as the path vanishing.
//
// The open now happens off the loop. This asserts the property that makes that
// safe: a session can be created, and datagrams accepted into it, before any
// stream exists.
func TestSessionAcceptsDatagramsBeforeItsStreamExists(t *testing.T) {
	s := &udpSession{out: make(chan dgram, udpQueueDepth), closed: make(chan struct{})}
	if s.stream.Load() != nil {
		t.Fatal("a new session must start with no stream")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		p := make([]byte, 1200)
		for i := 0; i < udpQueueDepth*4; i++ {
			s.offer(p) // must not block or panic with no stream present
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("accepting datagrams blocked while the stream was still being opened — " +
			"the socket read loop would stall and the kernel would discard the port's traffic")
	}
	if len(s.out) == 0 {
		t.Fatal("nothing was queued while the stream was being opened; those datagrams are lost")
	}
}

// A session whose stream never arrives must tear down cleanly rather than
// dereferencing a stream that was never set.
func TestTeardownWithoutAStreamIsSafe(t *testing.T) {
	s := &udpSession{out: make(chan dgram, 8), closed: make(chan struct{})}
	s.offer([]byte("queued before the open failed"))
	s.shutdown()
	s.drain() // must not panic on a nil stream, and must release what was queued
	if len(s.out) != 0 {
		t.Fatalf("%d datagram(s) left queued after teardown", len(s.out))
	}
}
