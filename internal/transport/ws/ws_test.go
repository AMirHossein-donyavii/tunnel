package ws

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
)

func pair(t *testing.T, cfg *config.Config) (net.Conn, net.Conn) {
	t.Helper()
	tr := &wsTransport{}
	log := logx.New(io.Discard, logx.ERROR)
	ln, err := tr.NewListener(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	dcfg := *cfg
	dcfg.Peer = "127.0.0.1"
	dcfg.TunnelPort = port
	d, err := tr.NewDialer(&dcfg, log)
	if err != nil {
		t.Fatal(err)
	}

	srv := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			srv <- c
		} else {
			close(srv)
		}
	}()
	cli, err := d.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	s, ok := <-srv
	if !ok {
		t.Fatal("server did not accept")
	}
	t.Cleanup(func() { cli.Close(); s.Close() })
	return cli, s
}

func TestWSRoundTrip(t *testing.T) {
	cli, srv := pair(t, &config.Config{TunnelPort: 0})

	// Sizes that exercise all three length encodings (7-bit, 16-bit, 64-bit).
	for _, n := range []int{1, 125, 126, 1000, 65535, 65536, 200000} {
		payload := bytes.Repeat([]byte{byte(n)}, n)
		go func() { _, _ = cli.Write(payload) }()
		got := make([]byte, n)
		if _, err := io.ReadFull(srv, got); err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("n=%d: payload mismatch", n)
		}
	}
	// And back the other way (server frames are unmasked).
	reply := []byte("pong from the server")
	go func() { _, _ = srv.Write(reply) }()
	got := make([]byte, len(reply))
	if _, err := io.ReadFull(cli, got); err != nil || !bytes.Equal(got, reply) {
		t.Fatalf("server->client: %v", err)
	}
}

// Client-to-server frames must be masked; server-to-client must not be. A
// middlebox or CDN that enforces RFC 6455 will drop the connection otherwise.
func TestWSMaskingDirection(t *testing.T) {
	var cbuf, sbuf bytes.Buffer
	c := newConn(nil, true)
	s := newConn(nil, false)
	cbuf.Write(c.appendFrame(nil, opBinary, []byte("hello")))
	sbuf.Write(s.appendFrame(nil, opBinary, []byte("hello")))

	if cbuf.Bytes()[1]&0x80 == 0 {
		t.Error("client frame is not masked")
	}
	if sbuf.Bytes()[1]&0x80 != 0 {
		t.Error("server frame is masked")
	}
	// A masked frame must not carry the plaintext verbatim.
	if bytes.Contains(cbuf.Bytes(), []byte("hello")) {
		t.Error("masked payload appears in cleartext")
	}
}

// A non-default path must answer anything else with a plain 404, so a probe
// sees an ordinary web server.
func TestWSWrongPathIsRejected(t *testing.T) {
	tr := &wsTransport{}
	log := logx.New(io.Discard, logx.ERROR)
	ln, err := tr.NewListener(&config.Config{TunnelPort: 0, WSPath: "/secret"}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	accepted := make(chan struct{})
	go func() { _, _ = ln.Accept(); close(accepted) }()

	d, _ := tr.NewDialer(&config.Config{Peer: "127.0.0.1", TunnelPort: port, WSPath: "/wrong"}, log)
	if _, err := d.Dial(context.Background()); err == nil {
		t.Fatal("dial with the wrong path succeeded")
	}
	select {
	case <-accepted:
		t.Fatal("listener accepted a connection on the wrong path")
	default:
	}
}

// Concurrent reader and writer is the contract the link layer relies on.
func TestWSConcurrentReadWrite(t *testing.T) {
	cli, srv := pair(t, &config.Config{TunnelPort: 0})
	const n = 200
	payload := bytes.Repeat([]byte("x"), 4096)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			if _, err := cli.Write(payload); err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		got := make([]byte, len(payload)*n)
		if _, err := io.ReadFull(srv, got); err != nil {
			t.Errorf("read: %v", err)
		}
	}()
	wg.Wait()
}

// Anything that is not a genuine tunnel connection must look like a website.
//
// The listener used to answer a 404 for a wrong path and a 400 for a
// non-upgrade request. Both are tells: a real site has a homepage, and a
// complaint that the request was not an upgrade announces that something here
// speaks WebSocket.
func TestProbeSeesAWebsite(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = serverHandshake(c, "/tunnel")
				c.Close()
			}()
		}
	}()

	probes := []struct {
		name, req string
	}{
		{"a browser opening the address", "GET / HTTP/1.1\r\nHost: x\r\n\r\n"},
		{"a scanner on another path", "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n"},
		{"an upgrade on the wrong path", "GET /wrong HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n\r\n"},
		{"an upgrade with no key", "GET /tunnel HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"},
		{"a POST", "POST /tunnel HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"},
	}
	for _, p := range probes {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(c, p.req)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		body, _ := io.ReadAll(c)
		c.Close()

		got := string(body)
		if !strings.HasPrefix(got, "HTTP/1.1 200 OK") {
			t.Errorf("%s: got %q, want a 200 — anything else marks the port",
				p.name, firstLine(got))
		}
		if !strings.Contains(got, "Welcome to nginx!") {
			t.Errorf("%s: no page body was served", p.name)
		}
		if !strings.Contains(got, "Server: nginx") {
			t.Errorf("%s: no ordinary server header", p.name)
		}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\r'); i >= 0 {
		return s[:i]
	}
	return s
}
