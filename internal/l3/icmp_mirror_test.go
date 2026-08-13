//go:build linux

package l3

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// A kernel answers an Echo Request by itself, copying the payload back verbatim.
// The dialer used to send requests, so the listening server's uplink carried a
// full copy of everything the dialer sent — the tunnel's entire download volume,
// on the server that usually has the smaller uplink. The real traffic in the
// other direction then queues behind that junk, which is what a tunnel that
// "feels slow to update" looks like from a chat app.
//
// This measures the kernel's behaviour directly rather than assuming it.
func TestEchoRepliesDrawNoKernelCopy(t *testing.T) {
	pc, err := icmp.ListenPacket("ip4:icmp", "127.0.0.1")
	if err != nil {
		t.Skip("raw ICMP sockets unavailable (needs CAP_NET_RAW)")
	}
	defer pc.Close()

	const id = 31337
	payload := bytes.Repeat([]byte{0xAB}, 1200)

	measure := func(reply bool) int {
		msg := appendTagged(nil, protoFor(config.TunModeICMP), reply, id, 1,
			tagToListener, 1234, payload)
		if _, err := pc.WriteTo(msg, &net.IPAddr{IP: net.ParseIP("127.0.0.1")}); err != nil {
			t.Fatalf("send: %v", err)
		}
		// On loopback our own packet is delivered back to us as well, so count by
		// ICMP type and subtract the one copy we sent.
		seen := map[byte]int{}
		bytesSeen := map[byte]int{}
		buf := make([]byte, 4096)
		deadline := time.Now().Add(700 * time.Millisecond)
		for time.Now().Before(deadline) {
			_ = pc.SetReadDeadline(deadline)
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				break
			}
			if n < icmpEchoHdr || int(buf[4])<<8|int(buf[5]) != id {
				continue
			}
			seen[buf[0]]++
			bytesSeen[buf[0]] += n
		}
		ours := byte(ipv4.ICMPTypeEchoReply)
		if !reply {
			ours = byte(ipv4.ICMPTypeEcho)
		}
		total := 0
		for typ, nb := range bytesSeen {
			c := seen[typ]
			if typ == ours {
				c--
				nb -= len(msg)
			}
			if c > 0 {
				total += nb
			}
		}
		return total
	}

	if got := measure(false); got == 0 {
		t.Skip("this kernel does not answer echo requests; the test cannot show the difference")
	} else {
		t.Logf("Echo Request drew %d bytes back from the kernel", got)
	}
	if got := measure(true); got != 0 {
		t.Fatalf("Echo Reply drew %d bytes back from the kernel — the copy this change "+
			"exists to remove is still there", got)
	}
}

// The listening side has to accept both, because a dialer on a path that drops
// unsolicited replies falls back to requests and must still connect.
func TestListenerAcceptsBothDirectionsFromTheDialer(t *testing.T) {
	cfg := &config.Config{TunnelPort: 4321, Cipher: "aes-256-gcm"}
	_, ll, err := newICMPCarrier(config.TunModeICMP, cfg, false, cfg.Cipher, logx.New(io.Discard, logx.INFO))
	if err != nil {
		t.Skip("raw ICMP sockets unavailable (needs CAP_NET_RAW)")
	}
	l := ll.(*icmpLinkListener)
	defer l.Close()

	pc, err := icmp.ListenPacket("ip4:icmp", "127.0.0.1")
	if err != nil {
		t.Skipf("raw ICMP unavailable: %v", err)
	}
	defer pc.Close()

	for _, tc := range []struct {
		name  string
		reply bool
		id    int
	}{
		{"a dialer sending Echo Replies", true, 111},
		{"a dialer that fell back to Echo Requests", false, 222},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := appendTagged(nil, protoFor(config.TunModeICMP), tc.reply, tc.id, 1,
				tagToListener, 4321, []byte("a frame"))
			if _, err := pc.WriteTo(msg, &net.IPAddr{IP: net.ParseIP("127.0.0.1")}); err != nil {
				t.Fatalf("send: %v", err)
			}
			if !sawFlow(l, 2*time.Second) {
				t.Fatal("the listener did not accept this dialer")
			}
		})
	}
}

// Sending replies must not make the listener read its own output: its frames are
// Echo Replies too now, and only the direction tag separates them.
func TestListenerDoesNotReadItsOwnReplies(t *testing.T) {
	own := appendTagged(nil, protoFor(config.TunModeICMP), true, 7, 1, tagToDialer, 4321, []byte("out"))
	data, _, ok := parseEchoAny(own, false)
	if !ok {
		t.Fatal("the listener's own frame did not parse as an echo")
	}
	if _, ok := stripTag(data, tagToListener, 4321); ok {
		t.Fatal("the listener accepted a frame it sent itself — with both directions " +
			"on the same ICMP type, the direction tag is the only thing separating them")
	}
}

// The dialer must not start assuming a mode, and must remember the one that
// worked so only the first link of the pool pays to find out.
func TestDialerRemembersTheModeThatWorked(t *testing.T) {
	d := &icmpLinkDialer{}
	if got := d.pick(); len(got) != 2 || got[0] != true || got[1] != false {
		t.Fatalf("a fresh dialer must try replies then requests, got %v", got)
	}
	d.mode.Store(icmpModeReply)
	if got := d.pick(); len(got) != 1 || got[0] != true {
		t.Fatalf("after replies worked the dialer must stop probing, got %v", got)
	}
	d.mode.Store(icmpModeRequest)
	if got := d.pick(); len(got) != 1 || got[0] != false {
		t.Fatalf("after falling back the dialer must stay fallen back, got %v", got)
	}
}

// End to end over loopback: a real dial, a real handshake, and frames both ways
// on the reply-only path. Every other test here checks one property in
// isolation; this is the one that would catch a change that makes the carrier
// stop working altogether.
func TestICMPLinkCarriesFramesBothWays(t *testing.T) {
	cfg := &config.Config{TunnelPort: 4444, Cipher: "aes-256-gcm", Profile: "fast", Peer: "127.0.0.1"}
	log := logx.New(io.Discard, logx.INFO)

	_, ll, err := newICMPCarrier(config.TunModeICMP, cfg, false, cfg.Cipher, log)
	if err != nil {
		t.Skip("raw ICMP sockets unavailable (needs CAP_NET_RAW)")
	}
	defer ll.Close()

	ld, _, err := newICMPCarrier(config.TunModeICMP, cfg, true, cfg.Cipher, log)
	if err != nil {
		t.Fatalf("dialer: %v", err)
	}
	defer ld.Close()

	type accepted struct {
		lk  link
		err error
	}
	acc := make(chan accepted, 1)
	go func() {
		lk, err := ll.AcceptLink()
		acc <- accepted{lk, err}
	}()

	client, err := ld.DialLink(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	var server link
	select {
	case a := <-acc:
		if a.err != nil {
			t.Fatalf("accept: %v", a.err)
		}
		server = a.lk
	case <-time.After(15 * time.Second):
		t.Fatal("the listener never accepted the link")
	}
	defer server.Close()

	// The dialer must have settled on replies: this is a clean loopback path.
	if got := ld.(*icmpLinkDialer).mode.Load(); got != icmpModeReply {
		t.Fatalf("dialer settled on mode %d, want replies (%d) — on a path that passes "+
			"them, falling back costs the peer an upload copy of everything we send",
			got, icmpModeReply)
	}

	up := bytes.Repeat([]byte("u"), 900)
	if err := client.WriteFrame(up); err != nil {
		t.Fatalf("dialer write: %v", err)
	}
	_ = server.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := server.ReadFrame()
	if err != nil {
		t.Fatalf("listener read: %v", err)
	}
	if !bytes.Equal(got, up) {
		t.Fatalf("listener got %d bytes, want %d", len(got), len(up))
	}

	down := bytes.Repeat([]byte("d"), 1100)
	if err := server.WriteFrame(down); err != nil {
		t.Fatalf("listener write: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err = client.ReadFrame()
	if err != nil {
		t.Fatalf("dialer read: %v", err)
	}
	if !bytes.Equal(got, down) {
		t.Fatalf("dialer got %d bytes, want %d", len(got), len(down))
	}
}

// Every link of the pool used to open its own raw ICMP socket. A raw socket has
// no port and no filter, so the kernel copies every ICMP packet the host
// receives into every one of them: four links meant four copies, four wakeups,
// four parses and three discards for each packet — work that grows with the
// square of the pool, on a server that is usually one core. One socket and a map
// from echo id costs one copy however many links there are.
func TestPoolSharesOneSocketAndEachLinkGetsItsOwnFrames(t *testing.T) {
	cfg := &config.Config{TunnelPort: 4555, Cipher: "aes-256-gcm", Profile: "fast", Peer: "127.0.0.1"}
	log := logx.New(io.Discard, logx.INFO)

	_, ll, err := newICMPCarrier(config.TunModeICMP, cfg, false, cfg.Cipher, log)
	if err != nil {
		t.Skip("raw ICMP sockets unavailable (needs CAP_NET_RAW)")
	}
	defer ll.Close()
	ld, _, err := newICMPCarrier(config.TunModeICMP, cfg, true, cfg.Cipher, log)
	if err != nil {
		t.Fatalf("dialer: %v", err)
	}
	defer ld.Close()

	const links = 4
	servers := make(chan link, links)
	go func() {
		for i := 0; i < links; i++ {
			lk, err := ll.AcceptLink()
			if err != nil {
				return
			}
			servers <- lk
		}
	}()

	clients := make([]link, 0, links)
	for i := 0; i < links; i++ {
		c, err := ld.DialLink(context.Background())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer c.Close()
		clients = append(clients, c)
	}

	d := ld.(*icmpLinkDialer)
	d.mu.Lock()
	nconns := len(d.conns)
	onePC := d.pc != nil
	d.mu.Unlock()
	if !onePC {
		t.Fatal("the dialer has no shared socket")
	}
	if nconns != links {
		t.Fatalf("%d links registered on the shared socket, want %d", nconns, links)
	}

	// Distinct echo ids: two links sharing one would read each other's frames,
	// which is the only thing the shared socket demultiplexes by.
	d.mu.Lock()
	ids := len(d.conns)
	d.mu.Unlock()
	if ids != links {
		t.Fatalf("%d distinct echo ids for %d links — a collision makes two links "+
			"read each other's traffic", ids, links)
	}

	// Each link must receive its own frame and only its own.
	srv := make([]link, 0, links)
	for i := 0; i < links; i++ {
		select {
		case s := <-servers:
			defer s.Close()
			srv = append(srv, s)
		case <-time.After(15 * time.Second):
			t.Fatalf("only %d of %d links were accepted", i, links)
		}
	}
	for i, c := range clients {
		payload := bytes.Repeat([]byte{byte('A' + i)}, 200+i)
		if err := c.WriteFrame(payload); err != nil {
			t.Fatalf("link %d write: %v", i, err)
		}
	}
	got := map[string]bool{}
	for range srv {
		for _, s := range srv {
			_ = s.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			if f, err := s.ReadFrame(); err == nil {
				got[string(f)] = true
			}
		}
	}
	for i := range clients {
		want := string(bytes.Repeat([]byte{byte('A' + i)}, 200+i))
		if !got[want] {
			t.Fatalf("the frame from link %d never arrived — %d of %d distinct frames landed",
				i, len(got), links)
		}
	}
}
