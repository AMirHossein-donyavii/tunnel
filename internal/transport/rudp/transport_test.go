package rudp

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
)

// Everything else in this package tests the ARQ and the FEC codec against a
// simulated link. Nothing tested the transport itself — a real dial to a real
// listener over a real UDP socket, carrying bytes both ways — and that is where
// it was broken: the connection was established and accepted, and then no data
// crossed it, so the tunnel's own handshake timed out on one side and read EOF
// on the other. Every unit test in the package passed the whole time.
//
// The other transports (ws, wss, stealth, quic) each have this round trip. This
// is the one that was missing.

func endpoints(t *testing.T, cfg config.Config) (net.Conn, net.Conn) {
	t.Helper()
	tr := &rudpTransport{}
	log := logx.New(io.Discard, logx.ERROR)

	srvCfg := cfg
	srvCfg.TunnelPort = 0 // ephemeral
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

	cliCfg := cfg
	cliCfg.Peer = "127.0.0.1"
	cliCfg.TunnelPort = ln.Addr().(*net.UDPAddr).Port
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

	select {
	case srv := <-accepted:
		t.Cleanup(func() { srv.Close() })
		return cli, srv
	case <-time.After(10 * time.Second):
		t.Fatal("listener never returned the peer")
	}
	return nil, nil
}

// The dialer speaks first, exactly as the tunnel's crypto handshake does.
func TestDialerToListener(t *testing.T) {
	cli, srv := endpoints(t, config.Config{})

	msg := []byte("client hello, as the crypto handshake would send it")
	if _, err := cli.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := make([]byte, len(msg))
	_ = srv.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(srv, got); err != nil {
		t.Fatalf("the listener never received what the dialer sent: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q want %q", got, msg)
	}
}

// And the reply must come back, which is where the handshake fails next.
func TestListenerToDialer(t *testing.T) {
	cli, srv := endpoints(t, config.Config{})

	// Introduce ourselves first: the listener only has a peer once it hears one.
	if _, err := cli.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	var in [5]byte
	_ = srv.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(srv, in[:]); err != nil {
		t.Fatalf("listener read: %v", err)
	}

	msg := []byte("server key, as the crypto handshake would answer")
	if _, err := srv.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	_ = cli.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(cli, got); err != nil {
		t.Fatalf("the dialer never received the listener's reply: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q want %q", got, msg)
	}
}

// A payload well past one MTU, so segmentation and reassembly are exercised —
// the tunnel moves nothing but large transfers once the handshake is done.
func TestCarriesAPayloadLargerThanTheMTU(t *testing.T) {
	cli, srv := endpoints(t, config.Config{})

	payload := bytes.Repeat([]byte("emergency tunnel over reliable udp"), 3000) // ~100 KB
	go func() { _, _ = cli.Write(payload) }()

	got := make([]byte, len(payload))
	_ = srv.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(srv, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload came back altered")
	}
}

// FEC changes the framing of every packet, including the first one the listener
// uses to recognise a new peer. It must still complete a round trip.
func TestRoundTripWithFECEnabled(t *testing.T) {
	cli, srv := endpoints(t, config.Config{FECData: 10, FECParity: 3})

	msg := bytes.Repeat([]byte("coded"), 500)
	go func() { _, _ = cli.Write(msg) }()

	got := make([]byte, len(msg))
	_ = srv.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(srv, got); err != nil {
		t.Fatalf("read with FEC on: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("payload came back altered with FEC on")
	}
}

// The engine runs several sessions at once over ONE listener socket. That is
// the shape the single-connection tests never had, and it is where driving the
// state machine from the receive path can go wrong: the listener demultiplexes
// every connection from a single read loop, so work done inline there is work
// every other connection waits behind.
func TestConcurrentConnectionsOverOneListener(t *testing.T) {
	tr := &rudpTransport{}
	log := logx.New(io.Discard, logx.ERROR)

	ln, err := tr.NewListener(&config.Config{TunnelPort: 0, Profile: "balance"}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.UDPAddr).Port

	const conns = 4
	const payload = 512 * 1024

	served := make(chan int64, conns)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
				n, err := io.Copy(io.Discard, io.LimitReader(c, payload))
				if err != nil {
					t.Errorf("connection delivered %d of %d bytes: %v", n, payload, err)
				}
				served <- n
			}(c)
		}
	}()

	d, err := tr.NewDialer(&config.Config{Peer: "127.0.0.1", TunnelPort: port, Profile: "balance"}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	buf := bytes.Repeat([]byte("x"), payload)
	for i := 0; i < conns; i++ {
		c, err := d.Dial(context.Background())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer c.Close()
		go func() { _, _ = c.Write(buf) }()
	}

	start := time.Now()
	var total int64
	for i := 0; i < conns; i++ {
		select {
		case n := <-served:
			total += n
		case <-time.After(30 * time.Second):
			t.Fatalf("only %d of %d connections delivered their payload in 30s "+
				"(%d bytes so far) — connections are starving each other", i, conns, total)
		}
	}
	if total != conns*payload {
		t.Fatalf("delivered %d bytes, want %d", total, conns*payload)
	}
	t.Logf("%d connections x %d KiB in %v (%.0f Mbit/s aggregate)",
		conns, payload/1024, time.Since(start).Round(time.Millisecond),
		float64(total)*8/time.Since(start).Seconds()/1e6)
}
