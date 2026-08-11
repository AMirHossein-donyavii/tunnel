package wss

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
)

func endpoints(t *testing.T, cfg config.Config) (net.Conn, net.Conn, int) {
	t.Helper()
	tr := &wssTransport{}
	log := logx.New(io.Discard, logx.ERROR)

	srvCfg := cfg
	srvCfg.TunnelPort = 0
	ln, err := tr.NewListener(&srvCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- c
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	cliCfg := cfg
	cliCfg.Peer, cliCfg.TunnelPort = "127.0.0.1", port
	d, err := tr.NewDialer(&cliCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := d.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { cli.Close() })

	select {
	case srv := <-accepted:
		t.Cleanup(func() { srv.Close() })
		return cli, srv, port
	case <-time.After(5 * time.Second):
		t.Fatal("listener never returned the peer")
	}
	return nil, nil, 0
}

func TestWSSCarriesData(t *testing.T) {
	cli, srv, _ := endpoints(t, config.Config{})
	go func() { _, _ = cli.Write([]byte("over https")) }()
	got := make([]byte, len("over https"))
	if _, err := io.ReadFull(srv, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "over https" {
		t.Fatalf("got %q", got)
	}
	go func() { _, _ = srv.Write([]byte("and back")) }()
	back := make([]byte, len("and back"))
	if _, err := io.ReadFull(cli, back); err != nil {
		t.Fatal(err)
	}
}

// The port must answer TLS like a web server, and serve a page to a browser
// rather than anything that identifies a tunnel.
func TestProbeGetsAWebsiteOverTLS(t *testing.T) {
	_, _, port := endpoints(t, config.Config{WSPath: "/tunnel"})

	c, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(port)),
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("the port did not complete TLS like a web server: %v", err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	body, _ := io.ReadAll(c)

	got := string(body)
	if !strings.HasPrefix(got, "HTTP/1.1 200 OK") {
		t.Fatalf("a browser got %q, want a 200", strings.SplitN(got, "\r\n", 2)[0])
	}
	if !strings.Contains(got, "Welcome to nginx!") {
		t.Fatal("no website was served to a browser")
	}
}

// The ClientHello must not be Go's. This checks the one thing that is cheap to
// verify without a full parser: Go's TLS stack and a Chrome fingerprint differ
// in the extensions they send, and Chrome's hello is substantially larger.
func TestClientHelloIsNotGos(t *testing.T) {
	capture := func(dial func(addr string)) []byte {
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
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, 4096)
			n, _ := c.Read(buf)
			got <- buf[:n]
		}()
		dial(ln.Addr().String())
		select {
		case b := <-got:
			return b
		case <-time.After(4 * time.Second):
			t.Fatal("no ClientHello observed")
		}
		return nil
	}

	goHello := capture(func(addr string) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return
		}
		defer c.Close()
		tc := tls.Client(c, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true})
		_ = tc.SetDeadline(time.Now().Add(time.Second))
		_ = tc.Handshake()
	})

	tr := &wssTransport{}
	log := logx.New(io.Discard, logx.ERROR)
	chromeHello := capture(func(addr string) {
		host, p, _ := net.SplitHostPort(addr)
		port := 0
		for _, ch := range p {
			port = port*10 + int(ch-'0')
		}
		d, err := tr.NewDialer(&config.Config{Peer: host, TunnelPort: port, TLSSNI: "example.com"}, log)
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, _ = d.Dial(ctx)
	})

	if len(goHello) == 0 || len(chromeHello) == 0 {
		t.Fatal("did not capture both handshakes")
	}
	if len(goHello) == len(chromeHello) {
		t.Fatalf("both ClientHellos are %d bytes — the browser fingerprint is not being used", len(goHello))
	}
	t.Logf("Go ClientHello %d bytes, Chrome fingerprint %d bytes", len(goHello), len(chromeHello))
}

// A stalled connection must not delay a real peer.
func TestSilentPeerDoesNotBlockAccept(t *testing.T) {
	tr := &wssTransport{}
	log := logx.New(io.Discard, logx.ERROR)
	ln, err := tr.NewListener(&config.Config{TunnelPort: 0}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close() // connected, says nothing: TLS never starts
	}

	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- c
		}
	}()

	d, _ := tr.NewDialer(&config.Config{Peer: "127.0.0.1", TunnelPort: port}, log)
	cli, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("a real peer was held up behind connections that said nothing")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
