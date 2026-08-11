package quic

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
)

func endpoints(t *testing.T, cfg config.Config) (net.Conn, net.Conn) {
	t.Helper()
	tr := &quicTransport{}
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

	port := ln.Addr().(*net.UDPAddr).Port
	cliCfg := cfg
	cliCfg.Peer, cliCfg.TunnelPort = "127.0.0.1", port
	d, err := tr.NewDialer(&cliCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	cli, err := d.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { cli.Close() })

	// A QUIC stream does not exist for the peer until it carries a byte, so the
	// listener cannot see this link until the client speaks — which is what the
	// tunnel's own handshake does. Send one byte to complete the introduction.
	if _, err := cli.Write([]byte{0}); err != nil {
		t.Fatalf("first write: %v", err)
	}

	select {
	case srv := <-accepted:
		t.Cleanup(func() { srv.Close() })
		var one [1]byte
		if _, err := io.ReadFull(srv, one[:]); err != nil {
			t.Fatalf("reading the introduction byte: %v", err)
		}
		return cli, srv
	case <-time.After(10 * time.Second):
		t.Fatal("listener never returned the peer")
	}
	return nil, nil
}

func TestQUICCarriesData(t *testing.T) {
	cli, srv := endpoints(t, config.Config{})

	payload := bytes.Repeat([]byte("emergency tunnel over quic"), 400)
	go func() {
		_, _ = cli.Write(payload)
	}()

	got := make([]byte, len(payload))
	_ = srv.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(srv, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload came back altered")
	}
}

func TestQUICIsBidirectional(t *testing.T) {
	cli, srv := endpoints(t, config.Config{})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = srv.Write([]byte("from the listener")) }()
	go func() { defer wg.Done(); _, _ = cli.Write([]byte("from the dialer")) }()
	wg.Wait()

	for _, tc := range []struct {
		name string
		c    net.Conn
		want string
	}{
		{"dialer reads", cli, "from the listener"},
		{"listener reads", srv, "from the dialer"},
	} {
		got := make([]byte, len(tc.want))
		_ = tc.c.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(tc.c, got); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if string(got) != tc.want {
			t.Fatalf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

// The engine opens several links and runs a mux session over each. They must
// all work, and — the reason for choosing QUIC — they are independent streams
// on one connection rather than one connection each.
func TestManyLinksShareOneConnection(t *testing.T) {
	tr := &quicTransport{}
	log := logx.New(io.Discard, logx.ERROR)

	srvCfg := config.Config{TunnelPort: 0}
	ln, err := tr.NewListener(&srvCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const links = 4
	accepted := make(chan net.Conn, links)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()

	cliCfg := config.Config{Peer: "127.0.0.1", TunnelPort: ln.Addr().(*net.UDPAddr).Port}
	d, err := tr.NewDialer(&cliCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	for i := 0; i < links; i++ {
		c, err := d.Dial(context.Background())
		if err != nil {
			t.Fatalf("link %d: %v", i, err)
		}
		defer c.Close()
		if _, err := c.Write([]byte{byte(i)}); err != nil {
			t.Fatalf("link %d write: %v", i, err)
		}
	}

	// Every link arrives, and they all share one UDP 4-tuple: one flow on the
	// wire, several independent streams inside it.
	seen := map[string]int{}
	for i := 0; i < links; i++ {
		select {
		case c := <-accepted:
			var one [1]byte
			_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(c, one[:]); err != nil {
				t.Fatalf("link %d never delivered its byte: %v", i, err)
			}
			seen[c.RemoteAddr().String()]++
			c.Close()
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d links were accepted", i, links)
		}
	}
	// One source address, carrying all of them: a single UDP flow on the wire.
	// (The dialer's own LocalAddr is a wildcard bind, so it is not comparable to
	// what the listener sees — the count per address is the property that matters.)
	if len(seen) != 1 {
		t.Fatalf("links came from %d addresses, want 1 shared connection: %v", len(seen), seen)
	}
	for addr, n := range seen {
		if n != links {
			t.Fatalf("connection %s carried %d of %d links", addr, n, links)
		}
	}
}

// A peer that connects and then says nothing must not delay a real one. This is
// the accept-path stall that has bitten this project before: handshaking inline
// in Accept charges every waiting peer for the silent one.
func TestSilentPeerDoesNotBlockAccept(t *testing.T) {
	tr := &quicTransport{}
	log := logx.New(io.Discard, logx.ERROR)

	srvCfg := config.Config{TunnelPort: 0}
	ln, err := tr.NewListener(&srvCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.UDPAddr).Port

	// Several peers that open a UDP socket at the listener and never speak QUIC.
	for i := 0; i < 5; i++ {
		c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = c.Write([]byte("not a quic packet"))
	}

	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- c
		}
	}()

	cliCfg := config.Config{Peer: "127.0.0.1", TunnelPort: port}
	d, err := tr.NewDialer(&cliCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	start := time.Now()
	cli, err := d.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial behind silent peers: %v", err)
	}
	defer cli.Close()
	if _, err := cli.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}

	select {
	case <-accepted:
		if el := time.Since(start); el > 5*time.Second {
			t.Fatalf("a real peer took %v to be accepted behind silent ones", el)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a real peer was never accepted while silent peers were pending")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
