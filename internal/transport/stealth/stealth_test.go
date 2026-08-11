package stealth

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
)

const testToken = "a-sufficiently-long-tunnel-token"

// pair returns a connected client/server pair over a real socket.
func pair(t *testing.T, clientToken, serverToken string) (net.Conn, net.Conn, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type res struct {
		c   net.Conn
		err error
	}
	srvCh := make(chan res, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			srvCh <- res{nil, err}
			return
		}
		c, err := ServerHandshake(raw, serverToken, 2*time.Second)
		if err != nil {
			raw.Close()
		}
		srvCh <- res{c, err}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cli, cerr := ClientHandshake(raw, clientToken, 2*time.Second)
	s := <-srvCh
	if cerr != nil || s.err != nil {
		if cli != nil {
			cli.Close()
		}
		raw.Close()
		if cerr != nil {
			return nil, nil, cerr
		}
		return nil, nil, s.err
	}
	return cli, s.c, nil
}

func TestStealthCarriesDataBothWays(t *testing.T) {
	cli, srv, err := pair(t, testToken, testToken)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	defer srv.Close()

	// Sizes that cross the record boundary, so framing and padding are both
	// exercised rather than just the easy case.
	for _, n := range []int{1, 100, maxRecord - 1, maxRecord, maxRecord + 1, 3 * maxRecord} {
		want := make([]byte, n)
		if _, err := rand.Read(want); err != nil {
			t.Fatal(err)
		}
		go func() { _, _ = cli.Write(want) }()
		got := make([]byte, n)
		if _, err := io.ReadFull(srv, got); err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%d bytes came back changed", n)
		}
	}

	go func() { _, _ = srv.Write([]byte("reply")) }()
	got := make([]byte, 5)
	if _, err := io.ReadFull(cli, got); err != nil || string(got) != "reply" {
		t.Fatalf("server->client: %q %v", got, err)
	}
}

// The property the transport exists for: a peer without the token gets nothing
// back at all, so a scan cannot tell this port from a closed one.
func TestWrongTokenGetsNoReply(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		if c, err := ServerHandshake(raw, testToken, time.Second); err == nil {
			c.Close()
		} else {
			raw.Close()
		}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	// Anything at all, with the wrong credential.
	junk := make([]byte, handshakeMsg)
	_, _ = rand.Read(junk)
	if _, err := raw.Write(junk); err != nil {
		t.Fatal(err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	n, err := raw.Read(buf)
	if err == nil && n > 0 {
		t.Fatalf("the listener answered an unauthenticated peer with %d byte(s) — it is fingerprintable", n)
	}
}

// Nothing constant may appear at a fixed offset, or the stream is matchable by
// exactly the kind of rule this replaces.
func TestHandshakeHasNoConstantBytes(t *testing.T) {
	const rounds = 24
	var first [][]byte
	for i := 0; i < rounds; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		seen := make(chan []byte, 1)
		go func() {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			b := make([]byte, handshakeMsg)
			if _, err := io.ReadFull(raw, b); err == nil {
				seen <- b
			}
			raw.Close()
		}()
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		go func() { _, _ = ClientHandshake(raw, testToken, time.Second) }()
		select {
		case b := <-seen:
			first = append(first, b)
		case <-time.After(2 * time.Second):
			t.Fatal("no handshake observed")
		}
		raw.Close()
		ln.Close()
	}

	// Every byte position must vary across connections.
	for pos := 0; pos < handshakeMsg; pos++ {
		v := first[0][pos]
		same := true
		for _, b := range first[1:] {
			if b[pos] != v {
				same = false
				break
			}
		}
		if same {
			t.Fatalf("byte %d is 0x%02x in all %d handshakes — a constant a filter can match", pos, v, rounds)
		}
	}
}

// Record lengths must not track payload lengths exactly, or the padding is not
// doing anything.
func TestRecordLengthsVaryForIdenticalPayloads(t *testing.T) {
	cli, srv, err := pair(t, testToken, testToken)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	defer srv.Close()

	sc := cli.(*conn)
	seen := map[int]bool{}
	for i := 0; i < 40; i++ {
		var buf bytes.Buffer
		probe := &conn{Conn: &nopConn{w: &buf}, send: sc.send}
		if err := probe.writeRecord([]byte("identical")); err != nil {
			t.Fatal(err)
		}
		seen[buf.Len()] = true
	}
	if len(seen) < 5 {
		t.Fatalf("40 identical payloads produced only %d distinct record lengths — padding is not varying", len(seen))
	}
}

type nopConn struct {
	net.Conn
	w io.Writer
}

func (n *nopConn) Write(p []byte) (int, error) { return n.w.Write(p) }

// A tampered record must fail rather than be delivered.
func TestTamperedRecordIsRejected(t *testing.T) {
	cli, srv, err := pair(t, testToken, testToken)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	defer srv.Close()

	raw := srv.(*conn).Conn
	// A record header claiming a plausible size, followed by junk.
	_, _ = raw.Write([]byte{0x00, 0x40})
	junk := make([]byte, 0x40)
	_, _ = rand.Read(junk)
	_, _ = raw.Write(junk)

	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	if _, err := cli.Read(buf); err == nil {
		t.Fatal("a forged record was accepted")
	}
}

// The transport must refuse to run without a usable token rather than come up
// authenticating nobody.
func TestTransportRequiresAToken(t *testing.T) {
	tr := &stealthTransport{}
	log := logx.New(io.Discard, logx.ERROR)
	for _, tok := range []string{"", "   ", "short"} {
		if _, err := tr.NewListener(&config.Config{TunnelPort: 0, Token: tok}, log); err == nil {
			t.Fatalf("token %q was accepted", tok)
		}
		if _, err := tr.NewDialer(&config.Config{Peer: "1.2.3.4", TunnelPort: 1, Token: tok}, log); err == nil {
			t.Fatalf("token %q was accepted by the dialer", tok)
		}
	}
}

// End to end through the registered transport, which is how the engines use it.
func TestTransportRoundTrip(t *testing.T) {
	tr := &stealthTransport{}
	log := logx.New(io.Discard, logx.ERROR)
	ln, err := tr.NewListener(&config.Config{TunnelPort: 0, Token: testToken}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- c
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	d, err := tr.NewDialer(&config.Config{Peer: "127.0.0.1", TunnelPort: port, Token: testToken}, log)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	var srv net.Conn
	select {
	case srv = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("listener never returned the peer")
	}
	defer srv.Close()

	go func() { _, _ = cli.Write([]byte("through the transport")) }()
	got := make([]byte, len("through the transport"))
	if _, err := io.ReadFull(srv, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "through the transport" {
		t.Fatalf("got %q", got)
	}
}

// A silent connection must not delay a real peer — the same failure the L3
// listeners had, which is easy to reintroduce in every new listener.
func TestSilentPeerDoesNotBlockAccept(t *testing.T) {
	tr := &stealthTransport{}
	log := logx.New(io.Discard, logx.ERROR)
	ln, err := tr.NewListener(&config.Config{TunnelPort: 0, Token: testToken}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	// Connect and say nothing, as a scanner does.
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}

	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- c
		}
	}()

	d, _ := tr.NewDialer(&config.Config{Peer: "127.0.0.1", TunnelPort: port, Token: testToken}, log)
	cli, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("a real peer was held up behind connections that said nothing")
	}
}
