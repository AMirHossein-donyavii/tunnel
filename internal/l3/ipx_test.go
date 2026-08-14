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
)

func ipxModes() []string { return []string{config.TunModeIPIP, config.TunModeGRE} }

// The whole carrier, end to end over loopback: a real raw socket, a real
// handshake, and frames both ways. Everything else here checks one property;
// this is the test that fails if the carrier stops working at all.
func TestIPXCarriesFramesBothWays(t *testing.T) {
	for _, mode := range ipxModes() {
		t.Run(mode, func(t *testing.T) {
			cfg := &config.Config{TunnelPort: 5100, Cipher: "aes-256-gcm",
				Profile: "fast", Peer: "127.0.0.1", ListenIP: "127.0.0.1"}
			log := logx.New(io.Discard, logx.INFO)

			_, ll, err := newIPXCarrier(mode, cfg, false, cfg.Cipher, log)
			if err != nil {
				t.Skipf("raw IP sockets unavailable (needs CAP_NET_RAW): %v", err)
			}
			defer ll.Close()
			ld, _, err := newIPXCarrier(mode, cfg, true, cfg.Cipher, log)
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

			down := bytes.Repeat([]byte("d"), 1200)
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
		})
	}
}

// A pool of links shares one raw socket — a raw socket has no port, so one per
// link would make the kernel copy every packet of that protocol into every one
// of them. Each link must still receive its own frames and only its own.
func TestIPXPoolSharesOneSocketAndSeparatesLinks(t *testing.T) {
	for _, mode := range ipxModes() {
		t.Run(mode, func(t *testing.T) {
			cfg := &config.Config{TunnelPort: 5200, Cipher: "aes-256-gcm",
				Profile: "fast", Peer: "127.0.0.1", ListenIP: "127.0.0.1"}
			log := logx.New(io.Discard, logx.INFO)

			_, ll, err := newIPXCarrier(mode, cfg, false, cfg.Cipher, log)
			if err != nil {
				t.Skipf("raw IP sockets unavailable: %v", err)
			}
			defer ll.Close()
			ld, _, err := newIPXCarrier(mode, cfg, true, cfg.Cipher, log)
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

			d := ld.(*ipxLinkDialer)
			d.mu.Lock()
			n, one := len(d.conns), d.pc != nil
			d.mu.Unlock()
			if !one {
				t.Fatal("the dialer has no shared socket")
			}
			if n != links {
				t.Fatalf("%d distinct link ids for %d links — a collision makes two links "+
					"read each other's frames", n, links)
			}

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
				if err := c.WriteFrame(bytes.Repeat([]byte{byte('A' + i)}, 300+i)); err != nil {
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
				if !got[string(bytes.Repeat([]byte{byte('A' + i)}, 300+i))] {
					t.Fatalf("the frame from link %d never arrived (%d of %d landed)",
						i, len(got), links)
				}
			}
		})
	}
}

// These protocols have no ports, so every raw socket for them on the host
// receives every packet: two tunnels on one server would read each other's
// frames, and each side would read its own output. The framing must reject
// both, plus somebody else's genuine GRE or IP-in-IP.
func TestIPXFramingSeparatesTunnelsDirectionsAndStrangers(t *testing.T) {
	for _, mode := range ipxModes() {
		t.Run(mode, func(t *testing.T) {
			p, _ := ipxProfileFor(mode)
			frame := []byte("a sealed frame")

			ours := appendIPX(nil, p, dirToListener, 1111, 7, frame)
			if got, link, ok := parseIPX(p, ours, dirToListener, 1111); !ok ||
				link != 7 || !bytes.Equal(got, frame) {
				t.Fatalf("our own frame was rejected: ok=%v link=%d", ok, link)
			}

			// Our own output, seen on our own socket.
			if _, _, ok := parseIPX(p, ours, dirToDialer, 1111); ok {
				t.Fatal("a frame travelling the other way was accepted")
			}
			// Another tunnel on this host.
			other := appendIPX(nil, p, dirToListener, 2222, 7, frame)
			if _, _, ok := parseIPX(p, other, dirToListener, 1111); ok {
				t.Fatal("another tunnel's frame was read as ours")
			}
			// Somebody else's real traffic on this protocol.
			for _, junk := range [][]byte{
				nil,
				{0x00},
				bytes.Repeat([]byte{0x45}, 40), // a plain IPv4 packet, as real IP-in-IP carries
			} {
				if _, _, ok := parseIPX(p, junk, dirToListener, 1111); ok {
					t.Fatalf("unrelated traffic was accepted as a tunnel frame: % x", junk)
				}
			}
		})
	}
}

// GRE devices on the path read the four-byte header. Emitting a malformed one
// invites a middlebox to drop the tunnel, so it has to be the real thing: no
// extension flags, version 0, carrying IPv4.
func TestGREHeaderIsWellFormed(t *testing.T) {
	out := appendIPX(nil, ipxGRE, dirToListener, 1234, 5, []byte("x"))
	if len(out) < greHdr {
		t.Fatal("no GRE header emitted")
	}
	if out[0] != 0 || out[1] != 0 {
		t.Fatalf("GRE flags/version are % x, want 00 00 (base protocol, no extensions)", out[:2])
	}
	if got := int(out[2])<<8 | int(out[3]); got != greProtoIPv4 {
		t.Fatalf("GRE protocol type is 0x%04x, want 0x%04x (IPv4)", got, greProtoIPv4)
	}
	// And a GRE packet with extension flags set is not ours.
	withKey := append([]byte{0x20, 0x00, 0x08, 0x00}, out[greHdr:]...)
	if _, _, ok := parseIPX(ipxGRE, withKey, dirToListener, 1234); ok {
		t.Fatal("a GRE packet with a key extension was accepted as ours")
	}
}

// IP-in-IP adds nothing of its own: a real one's payload is an opaque inner
// packet that routers do not inspect, so prepending anything would only cost
// bytes and make it less like the real thing.
func TestIPIPAddsNoProtocolHeader(t *testing.T) {
	frame := []byte("sealed")
	out := appendIPX(nil, ipxIPIP, dirToListener, 1234, 5, frame)
	if len(out) != ipxHdr+len(frame) {
		t.Fatalf("IP-in-IP framing is %d bytes over the payload, want %d",
			len(out)-len(frame), ipxHdr)
	}
}

// The listening side must name a peer whose tunnel_port does not match, because
// that produces exactly the same silence as a stranger's traffic and means the
// tunnel will never come up.
func TestIPXMismatchedTunnelPortIsExplained(t *testing.T) {
	var out bytes.Buffer
	cfg := &config.Config{TunnelPort: 1111, Cipher: "aes-256-gcm", ListenIP: "127.0.0.1"}
	_, ll, err := newIPXCarrier(config.TunModeGRE, cfg, false, cfg.Cipher, logx.New(&out, logx.INFO))
	if err != nil {
		t.Skipf("raw IP sockets unavailable: %v", err)
	}
	l := ll.(*ipxLinkListener)
	defer l.Close()

	src := &net.IPAddr{IP: net.ParseIP("203.0.113.9")}
	theirs := appendIPX(nil, ipxGRE, dirToListener, 2222, 3, []byte("frame"))
	for i := 0; i < 20; i++ {
		l.reportMismatch(src, theirs)
	}
	got := out.String()
	for _, want := range []string{"203.0.113.9", "2222", "1111"} {
		if !bytes.Contains([]byte(got), []byte(want)) {
			t.Fatalf("the log does not mention %q:\n%s", want, got)
		}
	}
	// Somebody else's real GRE must stay silent.
	out.Reset()
	l.reportMismatch(src, append([]byte{0, 0, 0x08, 0x00}, bytes.Repeat([]byte{0x45}, 20)...))
	if out.Len() != 0 {
		t.Fatalf("unrelated GRE traffic was reported as a misconfigured peer: %s", out.String())
	}
}
