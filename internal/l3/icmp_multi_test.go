//go:build linux

package l3

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
	"golang.org/x/net/icmp"
)

// ICMP has no ports, and a raw ICMP socket receives a copy of every ICMP packet
// the host receives — not the subset addressed to one listener, because there is
// no such thing. Two ICMP tunnels on one server therefore see all of each
// other's traffic, and the echo id cannot separate them: each dialer picks its
// ids at random, so a listener cannot know which are its own.
//
// The result on a server running two ICMP tunnels — two Foreign servers dialing
// in, different tunnel ports, different subnets, exactly what the console builds
// — was that each listener answered the other's peer, each dialer accepted those
// replies as its own listener's, and both links carried two interleaved
// ciphertext streams. Both tunnels break and neither log says why.
//
// The configured tunnel port is what separates them.
func TestTwoICMPTunnelsOnOneHostDoNotCrossTalk(t *testing.T) {
	a, aOK := icmpListenerFor(t, 1111)
	if !aOK {
		t.Skip("raw ICMP sockets unavailable (needs CAP_NET_RAW)")
	}
	defer a.Close()
	b, _ := icmpListenerFor(t, 2222)
	defer b.Close()

	// One frame from the dialer of the tunnel on port 1111.
	pc, err := icmp.ListenPacket("ip4:icmp", "127.0.0.1")
	if err != nil {
		t.Skipf("raw ICMP unavailable: %v", err)
	}
	defer pc.Close()
	msg := appendEcho(nil, protoFor(config.TunModeICMP), 4242, 1, tagToListener, 1111,
		[]byte("a frame belonging to the tunnel on 1111"))
	if _, err := pc.WriteTo(msg, &net.IPAddr{IP: net.ParseIP("127.0.0.1")}); err != nil {
		t.Fatalf("send: %v", err)
	}

	if !sawFlow(a, 2*time.Second) {
		t.Fatal("the listener the frame belongs to never saw it")
	}
	if sawFlow(b, 500*time.Millisecond) {
		t.Fatal("the other tunnel's listener accepted a frame that is not its own — " +
			"it will answer that peer, and neither dialer can tell the two apart")
	}
}

// The same separation has to hold on the dialer side, where a reply from the
// other tunnel's listener arrives with an equally valid direction tag.
func TestDialerRejectsAnotherTunnelsReply(t *testing.T) {
	p := protoFor(config.TunModeICMP)
	const myID = 7

	mine := appendReply(nil, p, myID, 1, tagToDialer, 1111, []byte("mine"))
	// Same host, same echo id — a collision between two random ids is not rare
	// enough to rely on, and it is the only thing that used to separate them.
	theirs := appendReply(nil, p, myID, 1, tagToDialer, 2222, []byte("theirs"))

	got, ok := parseEcho(p, mine, myID, true)
	if !ok {
		t.Fatal("our own reply did not parse")
	}
	if _, ok := stripTag(got, tagToDialer, 1111); !ok {
		t.Fatal("a reply from this tunnel was rejected")
	}

	got, ok = parseEcho(p, theirs, myID, true)
	if !ok {
		t.Fatal("the other tunnel's reply did not parse; the test no longer exercises the case")
	}
	if _, ok := stripTag(got, tagToDialer, 1111); ok {
		t.Fatal("a reply belonging to another tunnel on this host was read as ours")
	}
}

func icmpListenerFor(t *testing.T, port int) (*icmpLinkListener, bool) {
	t.Helper()
	cfg := &config.Config{TunnelPort: port, Cipher: "aes-256-gcm"}
	_, l, err := newICMPCarrier(config.TunModeICMP, cfg, false, cfg.Cipher, logx.New(io.Discard, logx.INFO))
	if err != nil {
		return nil, false
	}
	return l.(*icmpLinkListener), true
}

func sawFlow(l *icmpLinkListener, d time.Duration) bool {
	select {
	case <-l.accept:
		return true
	case <-time.After(d):
		return false
	}
}

// A peer configured with a different tunnel_port produces the same silence as a
// neighbouring tunnel's traffic: frames arrive, are not ours, and are dropped.
// The difference is that this one means the tunnel will never come up, so it has
// to be said out loud — otherwise the symptom is a dead tunnel with an empty log.
func TestMismatchedTunnelPortIsExplained(t *testing.T) {
	var out bytes.Buffer
	cfg := &config.Config{TunnelPort: 1111, Cipher: "aes-256-gcm"}
	_, ll, err := newICMPCarrier(config.TunModeICMP, cfg, false, cfg.Cipher,
		logx.New(&out, logx.INFO))
	if err != nil {
		t.Skip("raw ICMP sockets unavailable (needs CAP_NET_RAW)")
	}
	l := ll.(*icmpLinkListener)
	defer l.Close()

	src := &net.IPAddr{IP: net.ParseIP("203.0.113.7")}
	// What a peer set to tunnel_port 2222 sends us.
	frame := appendTag(nil, tagToListener, 2222)
	for i := 0; i < 50; i++ {
		l.reportMismatch(src, frame)
	}

	got := out.String()
	for _, want := range []string{"203.0.113.7", "2222", "1111", "tunnel_port"} {
		if !strings.Contains(got, want) {
			t.Fatalf("the log does not mention %q, so the operator cannot act on it:\n%s", want, got)
		}
	}
	if n := strings.Count(got, "icmp: frames from"); n != 1 {
		t.Fatalf("logged %d times for one source; a peer retries several times a second "+
			"and would bury the rest of the log", n)
	}

	// Ordinary ping traffic must stay silent.
	out.Reset()
	l.reportMismatch(src, []byte("plain ping payload"))
	if out.Len() != 0 {
		t.Fatalf("a plain ping was reported as a misconfigured peer: %s", out.String())
	}
}
