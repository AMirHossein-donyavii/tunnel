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
