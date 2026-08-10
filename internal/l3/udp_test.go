package l3

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// TestUDPLinkRoundTrip exercises the full UDP carrier: datagram handshake over
// real loopback sockets, then a frame in each direction.
func TestUDPLinkRoundTrip(t *testing.T) {
	for _, cipher := range []string{"chacha20-poly1305", "aes-256-gcm"} {
		t.Run(cipher, func(t *testing.T) {
			ln, err := newUDPListener(0, 0, 0, cipher)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			port := ln.pc.LocalAddr().(*net.UDPAddr).Port

			srv := make(chan link, 1)
			go func() {
				if lk, err := ln.AcceptLink(); err == nil {
					srv <- lk
				}
			}()

			d := &udpLinkDialer{addr: fmt.Sprintf("127.0.0.1:%d", port), cipher: cipher}
			clk, err := d.DialLink(context.Background())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer clk.Close()

			var slk link
			select {
			case slk = <-srv:
			case <-time.After(3 * time.Second):
				t.Fatal("server did not accept the link")
			}
			defer slk.Close()

			// client -> server
			payload := appendPacket(nil, []byte("hello-udp-tunnel"))
			if err := clk.WriteFrame(payload); err != nil {
				t.Fatal(err)
			}
			got, err := slk.ReadFrame()
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("c->s frame: got %d bytes err=%v", len(got), err)
			}

			// server -> client
			reply := appendPacket(nil, bytes.Repeat([]byte{0xAB}, 1200))
			if err := slk.WriteFrame(reply); err != nil {
				t.Fatal(err)
			}
			got, err = clk.ReadFrame()
			if err != nil || !bytes.Equal(got, reply) {
				t.Fatalf("s->c frame: got %d bytes err=%v", len(got), err)
			}
		})
	}
}

func TestUDPHandshakeWrongMagic(t *testing.T) {
	ln, err := newUDPListener(0, 0, 0, "chacha20-poly1305")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.pc.LocalAddr().(*net.UDPAddr).Port

	done := make(chan struct{})
	go func() {
		// AcceptLink should skip the bad flow and keep waiting; close ends it.
		_, _ = ln.AcceptLink()
		close(done)
	}()

	// Send junk (no valid hello) then close.
	c, _ := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	_, _ = c.Write([]byte("not-a-handshake"))
	_ = c.Close()
	time.Sleep(100 * time.Millisecond)
	ln.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("AcceptLink did not return after close")
	}
}
