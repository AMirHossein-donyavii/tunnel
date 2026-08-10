package crypto

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func handshakePair(t *testing.T, cipher string) (*SecureConn, *SecureConn, error) {
	t.Helper()
	c1, c2 := net.Pipe()
	type res struct {
		sc  *SecureConn
		err error
	}
	cli := make(chan res, 1)
	go func() {
		sc, err := ClientHandshake(c1, cipher)
		cli <- res{sc, err}
	}()
	srv, serr := ServerHandshake(c2, cipher)
	cr := <-cli
	if serr != nil {
		return nil, nil, serr
	}
	if cr.err != nil {
		return nil, nil, cr.err
	}
	return cr.sc, srv, nil
}

func TestHandshakeAndAEAD(t *testing.T) {
	for _, cipher := range []string{"chacha20-poly1305", "aes-256-gcm"} {
		t.Run(cipher, func(t *testing.T) {
			client, server, err := handshakePair(t, cipher)
			if err != nil {
				t.Fatalf("handshake: %v", err)
			}
			defer client.Close()
			defer server.Close()

			// client -> server (spans multiple frames)
			msg := bytes.Repeat([]byte("emergency-tunnel "), 2000)
			go func() { _, _ = client.Write(msg) }()
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(server, got); err != nil {
				t.Fatalf("read: %v", err)
			}
			if !bytes.Equal(got, msg) {
				t.Fatal("client->server payload mismatch")
			}

			// server -> client
			reply := []byte("pong")
			go func() { _, _ = server.Write(reply) }()
			rb := make([]byte, len(reply))
			if _, err := io.ReadFull(client, rb); err != nil {
				t.Fatalf("read reply: %v", err)
			}
			if !bytes.Equal(rb, reply) {
				t.Fatal("server->client payload mismatch")
			}
		})
	}
}

func TestHandshakeRejectsBadMagic(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		// Send junk that is not a valid client hello.
		_ = c1.SetDeadline(time.Now().Add(time.Second))
		_, _ = c1.Write(bytes.Repeat([]byte{0xFF}, 37))
	}()
	if _, err := ServerHandshake(c2, "chacha20-poly1305"); err == nil {
		t.Fatal("expected handshake failure on bad magic")
	}
}

// TestFrameAPIRoundTrip exercises the message-oriented path used by the L3
// engine, including a full-size frame.
func TestFrameAPIRoundTrip(t *testing.T) {
	for _, cipher := range []string{"chacha20-poly1305", "aes-256-gcm"} {
		t.Run(cipher, func(t *testing.T) {
			client, server, err := handshakePair(t, cipher)
			if err != nil {
				t.Fatalf("handshake: %v", err)
			}
			defer client.Close()
			defer server.Close()

			frames := [][]byte{
				[]byte("small"),
				bytes.Repeat([]byte{0x5A}, 60*1024),
				bytes.Repeat([]byte{0xA5}, MaxPlaintext),
				{0x01},
			}
			go func() {
				for _, f := range frames {
					if err := client.WriteFrame(f); err != nil {
						return
					}
				}
			}()
			for i, want := range frames {
				got, err := server.NextFrame()
				if err != nil {
					t.Fatalf("frame %d: %v", i, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("frame %d: got %d bytes, want %d", i, len(got), len(want))
				}
			}
		})
	}
}

func TestWriteFrameRejectsOversized(t *testing.T) {
	client, server, err := handshakePair(t, "chacha20-poly1305")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()
	if err := client.WriteFrame(make([]byte, MaxPlaintext+1)); err != ErrFrameTooLarge {
		t.Fatalf("got %v, want ErrFrameTooLarge", err)
	}
}

// A frame must reach the wire in a single write. Two writes (one for the length
// prefix, one for the body) put a 2-byte segment in front of every frame once
// TCP_NODELAY is on, which is pure overhead on the tunnel's hot path.
func TestFrameIsOneWrite(t *testing.T) {
	cw := &countingConn{Conn: nopConn{}}
	sc, err := wrap(cw, "chacha20-poly1305", make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.WriteFrame(bytes.Repeat([]byte{1}, 4096)); err != nil {
		t.Fatal(err)
	}
	if cw.writes != 1 {
		t.Fatalf("WriteFrame issued %d writes, want 1", cw.writes)
	}
	cw.writes = 0
	// A stream write larger than one frame still coalesces its frames.
	if _, err := sc.Write(bytes.Repeat([]byte{2}, DefaultFrameSize*3)); err != nil {
		t.Fatal(err)
	}
	if cw.writes != 1 {
		t.Fatalf("Write issued %d writes for 3 frames, want 1 coalesced write", cw.writes)
	}
}

// SetFrameSize clamps to the supported range.
func TestSetFrameSizeClamps(t *testing.T) {
	sc, err := wrap(nopConn{}, "chacha20-poly1305", make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sc.SetFrameSize(1)
	if sc.frameSize != 1024 {
		t.Errorf("frameSize = %d, want 1024", sc.frameSize)
	}
	sc.SetFrameSize(1 << 30)
	if sc.frameSize != MaxPlaintext {
		t.Errorf("frameSize = %d, want %d", sc.frameSize, MaxPlaintext)
	}
}

func TestDatagramReplayWindow(t *testing.T) {
	send, err := newDatagram("chacha20-poly1305", make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	recv, err := newDatagram("chacha20-poly1305", make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}

	pkt := send.Seal(nil, []byte("payload"))
	dup := append([]byte(nil), pkt...)

	if _, err := recv.Open(nil, pkt); err != nil {
		t.Fatalf("first delivery rejected: %v", err)
	}
	if _, err := recv.Open(nil, dup); err != ErrReplay {
		t.Fatalf("replay accepted: %v", err)
	}
}

// Reordering within the window must still be accepted — real paths reorder, and
// dropping those packets would look like loss to the inner protocols.
func TestDatagramToleratesReordering(t *testing.T) {
	send, _ := newDatagram("chacha20-poly1305", make([]byte, 32), make([]byte, 32))
	recv, _ := newDatagram("chacha20-poly1305", make([]byte, 32), make([]byte, 32))

	var pkts [][]byte
	for i := 0; i < 64; i++ {
		pkts = append(pkts, send.Seal(nil, []byte{byte(i)}))
	}
	// Deliver in reverse order.
	for i := len(pkts) - 1; i >= 0; i-- {
		if _, err := recv.Open(nil, pkts[i]); err != nil {
			t.Fatalf("reordered packet %d rejected: %v", i, err)
		}
	}
	// Every one of them must now be rejected as a replay.
	for i := range pkts {
		if _, err := recv.Open(nil, pkts[i]); err != ErrReplay {
			t.Fatalf("packet %d replayed successfully: %v", i, err)
		}
	}
}

// A counter far beyond the window must not wipe out replay protection for the
// packets that follow it.
func TestDatagramWindowSlide(t *testing.T) {
	send, _ := newDatagram("chacha20-poly1305", make([]byte, 32), make([]byte, 32))
	recv, _ := newDatagram("chacha20-poly1305", make([]byte, 32), make([]byte, 32))

	first := send.Seal(nil, []byte("a"))
	if _, err := recv.Open(nil, first); err != nil {
		t.Fatal(err)
	}
	// Jump the sender well past the window width.
	for i := 0; i < replayWindowBits*2; i++ {
		send.Seal(nil, []byte("skip"))
	}
	far := send.Seal(nil, []byte("b"))
	if _, err := recv.Open(nil, far); err != nil {
		t.Fatalf("far-future packet rejected: %v", err)
	}
	if _, err := recv.Open(nil, far); err != ErrReplay {
		t.Fatal("replay of the far-future packet accepted")
	}
	// The original packet is now far below the window and must be refused.
	if _, err := recv.Open(nil, first); err != ErrReplay {
		t.Fatal("stale packet below the window accepted")
	}
}

// ---- helpers ----------------------------------------------------------------

type nopConn struct{ net.Conn }

func (nopConn) Write(p []byte) (int, error) { return len(p), nil }
func (nopConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (nopConn) Close() error                { return nil }

type countingConn struct {
	net.Conn
	writes int
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.writes++
	return len(p), nil
}

func BenchmarkWriteFrame(b *testing.B) {
	sc, err := wrap(nopConn{}, "chacha20-poly1305", make([]byte, 32), make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte{7}, 60*1024)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := sc.WriteFrame(payload); err != nil {
			b.Fatal(err)
		}
	}
}
