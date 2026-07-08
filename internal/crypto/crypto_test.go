package crypto

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func handshakePair(t *testing.T, cipher string, cpsk, spsk []byte) (*SecureConn, *SecureConn, error) {
	t.Helper()
	c1, c2 := net.Pipe()
	now := time.Now().Unix()
	type res struct {
		sc  *SecureConn
		err error
	}
	cli := make(chan res, 1)
	go func() {
		sc, err := ClientHandshake(c1, cipher, cpsk, now)
		cli <- res{sc, err}
	}()
	srv, serr := ServerHandshake(c2, cipher, spsk, now)
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
			psk := bytes.Repeat([]byte{0x42}, 32)
			client, server, err := handshakePair(t, cipher, psk, psk)
			if err != nil {
				t.Fatalf("handshake: %v", err)
			}
			defer client.Close()
			defer server.Close()

			// client -> server
			msg := bytes.Repeat([]byte("emergency-tunnel "), 2000) // spans multiple frames
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

func TestHandshakeRejectsWrongPSK(t *testing.T) {
	_, _, err := handshakePair(t, "chacha20-poly1305",
		bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err == nil {
		t.Fatal("expected handshake failure with mismatched PSK")
	}
}
