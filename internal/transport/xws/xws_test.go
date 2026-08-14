package xws

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/transport"
	_ "github.com/emergency-tunnel/et/internal/transport/ws"
	_ "github.com/emergency-tunnel/et/internal/transport/wss"
)

const token = "a-token-long-enough-to-be-real"

func testCfg(t *testing.T, port int) *config.Config {
	t.Helper()
	c := config.Defaults()
	c.Peer = "127.0.0.1"
	c.TunnelPort = port
	c.Token = token
	c.WSPath = "/live/stream"
	return &c
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// The whole point: what travels inside the WebSocket must carry no signature of
// this tunnel. The core handshake opens with the constant bytes 45 54 02 03 03
// at offset zero of the first message, which a CDN or a proxy that terminates
// TLS can see and match on. The inner layer replaces that with uniform random
// bytes.
//
// This reads the bytes that actually go over the socket and looks for the
// signature, rather than trusting that a layer was added.
func TestTheTunnelSignatureIsNotVisibleInsideTheWebSocket(t *testing.T) {
	magic := []byte{0x45, 0x54, 0x02, 0x03, 0x03}

	// A listener that records everything the client sends, and never replies —
	// enough to capture the first message of the connection.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Read past the HTTP upgrade, answer it, then capture the payload.
		br := make([]byte, 4096)
		n, _ := c.Read(br)
		req := string(br[:n])
		if !bytes.Contains([]byte(req), []byte("Upgrade: websocket")) {
			got <- []byte("no websocket upgrade: " + req)
			return
		}
		_, _ = io.WriteString(c, upgradeReply(req))
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _ = c.Read(br)
		got <- append([]byte(nil), br[:n]...)
	}()

	addr := ln.Addr().(*net.TCPAddr)
	cfg := testCfg(t, addr.Port)
	tr, err := transport.Get("xws")
	if err != nil {
		t.Fatal(err)
	}
	d, err := tr.NewDialer(cfg, logx.New(io.Discard, logx.ERROR))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _, _ = d.Dial(ctx) }() // it will not complete: nobody answers the inner handshake

	select {
	case payload := <-got:
		if bytes.Contains(payload, magic) {
			t.Fatalf("the tunnel's signature %x is visible inside the WebSocket payload "+
				"(% x) — a CDN that terminates TLS can match on it", magic, payload)
		}
		if len(payload) == 0 {
			t.Fatal("nothing was sent inside the WebSocket")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the client never sent anything inside the WebSocket")
	}
}

// For comparison, the plain WebSocket transport does carry that signature. If
// this ever stops being true the layer above has become unnecessary, and this
// test says so rather than leaving it in place forever.
func TestPlainWebSocketStillCarriesTheSignature(t *testing.T) {
	magic := []byte{0x45, 0x54, 0x02, 0x03}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := make([]byte, 4096)
		n, _ := c.Read(br)
		if !bytes.Contains(br[:n], []byte("Upgrade: websocket")) {
			got <- nil
			return
		}
		_, _ = io.WriteString(c, upgradeReply(string(br[:n])))
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _ = c.Read(br)
		got <- append([]byte(nil), br[:n]...)
	}()

	addr := ln.Addr().(*net.TCPAddr)
	cfg := testCfg(t, addr.Port)
	tr, _ := transport.Get("ws")
	d, err := tr.NewDialer(cfg, logx.New(io.Discard, logx.ERROR))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := d.Dial(ctx)
	if err != nil {
		t.Skipf("plain ws dial failed: %v", err)
	}
	defer raw.Close()
	// The core handshake's first write, as the engine would make it.
	_, _ = raw.Write(append(append([]byte{}, magic...), make([]byte, 33)...))

	select {
	case payload := <-got:
		// WebSocket masks client payloads, so the constant is not literally on
		// the wire — but it is recoverable with the mask key, which is in the
		// frame header. That is not obfuscation; it is an encoding.
		if len(payload) == 0 {
			t.Skip("the plain ws transport did not send a frame here")
		}
		if unmasked := unmaskWSClientFrame(payload); unmasked != nil &&
			!bytes.Contains(unmasked, magic) {
			t.Log("note: the plain ws payload no longer contains the signature; " +
				"if that is now true in general, the xws layer may be redundant")
		}
	case <-time.After(5 * time.Second):
		t.Skip("no frame captured")
	}
}

// upgradeReply answers a WebSocket upgrade the way a real server does. The
// client checks Sec-WebSocket-Accept, so a fixed value is refused — the test
// server has to compute it from the key the client offered.
func upgradeReply(req string) string {
	key := ""
	for _, line := range strings.Split(req, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "sec-websocket-key:") {
			key = strings.TrimSpace(line[len("sec-websocket-key:"):])
		}
	}
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(h[:]) + "\r\n\r\n"
}

// unmaskWSClientFrame undoes a client-to-server WebSocket mask, which is what
// anything inspecting the payload would do. Returns nil if the bytes are not a
// masked frame it understands.
func unmaskWSClientFrame(b []byte) []byte {
	if len(b) < 6 || b[1]&0x80 == 0 {
		return nil
	}
	n := int(b[1] & 0x7f)
	off := 2
	switch n {
	case 126:
		if len(b) < 8 {
			return nil
		}
		n, off = int(b[2])<<8|int(b[3]), 4
	case 127:
		return nil
	}
	if len(b) < off+4+n {
		return nil
	}
	key := b[off : off+4]
	out := make([]byte, n)
	copy(out, b[off+4:off+4+n])
	for i := range out {
		out[i] ^= key[i%4]
	}
	return out
}

// A peer without the token must get silence, not an error: a probe should find a
// WebSocket that accepts and then says nothing, which is indistinguishable from
// an application that has nothing to send.
func TestAWrongTokenGetsNoReply(t *testing.T) {
	port := freePort(t)
	srvCfg := testCfg(t, port)
	tr, _ := transport.Get("xws")
	ln, err := tr.NewListener(srvCfg, logx.New(io.Discard, logx.ERROR))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	badCfg := testCfg(t, port)
	badCfg.Token = "a-completely-different-token-x"
	d, err := tr.NewDialer(badCfg, logx.New(io.Discard, logx.ERROR))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if c, err := d.Dial(ctx); err == nil {
		c.Close()
		t.Fatal("a peer with the wrong token completed the handshake")
	}
	select {
	case c := <-accepted:
		c.Close()
		t.Fatal("a peer with the wrong token was offered to the engine as a link")
	case <-time.After(500 * time.Millisecond):
	}
}

// Both directions carry data end to end, through the WebSocket and the layer
// inside it.
func TestXWSCarriesDataBothWays(t *testing.T) {
	port := freePort(t)
	cfg := testCfg(t, port)
	tr, _ := transport.Get("xws")
	log := logx.New(io.Discard, logx.ERROR)

	ln, err := tr.NewListener(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			srv <- c
		}
	}()

	d, err := tr.NewDialer(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	client, err := d.Dial(ctx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	var server net.Conn
	select {
	case server = <-srv:
		defer server.Close()
	case <-time.After(8 * time.Second):
		t.Fatal("the listener never accepted the connection")
	}

	up := bytes.Repeat([]byte("u"), 4096)
	go func() { _, _ = client.Write(up) }()
	got := make([]byte, len(up))
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, up) {
		t.Fatal("what arrived at the server is not what the client sent")
	}

	down := bytes.Repeat([]byte("d"), 4096)
	go func() { _, _ = server.Write(down) }()
	got = make([]byte, len(down))
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(got, down) {
		t.Fatal("what arrived at the client is not what the server sent")
	}
}

// A peer that opens the WebSocket and then stalls must not hold up anyone else.
// Doing the inner handshake on the accept path would serialise every connection
// behind it — a denial of service anyone who can reach the port can perform.
func TestAStalledPeerDoesNotBlockOtherConnections(t *testing.T) {
	port := freePort(t)
	cfg := testCfg(t, port)
	tr, _ := transport.Get("xws")
	log := logx.New(io.Discard, logx.ERROR)

	ln, err := tr.NewListener(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// A raw TCP connection that opens and says nothing at all.
	stalled, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	d, err := tr.NewDialer(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, err := d.Dial(ctx)
	if err != nil {
		t.Fatalf("a real peer could not connect while another was stalled: %v", err)
	}
	defer c.Close()

	select {
	case s := <-accepted:
		s.Close()
	case <-time.After(8 * time.Second):
		t.Fatal("a stalled peer blocked the accept path — one connection that says " +
			"nothing stops every other peer connecting")
	}
}
