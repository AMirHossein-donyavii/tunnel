//go:build linux

package l3

import (
	"os"
	"testing"

	"github.com/emergency-tunnel/et/internal/config"
)

// The carrier can be named two ways: the pair the field uses (an encapsulation
// and, for the raw-IP family, a profile), or one word. They must always mean the
// same thing, and a config written back must read the same next time.
func TestCarrierNamingsAgree(t *testing.T) {
	base := func() *config.Config {
		d := config.Defaults()
		c := &d
		c.Engine = config.EngineTUN
		c.Name = "t"
		c.Role = config.RoleIran
		c.Mode = config.ModeReverse
		c.TunnelPort = 1234
		c.TunIP = "10.9.0.1/30"
		c.PeerTunIP = "10.9.0.2"
		c.Peer = "203.0.113.1"
		return c
	}

	for _, tc := range []struct {
		name       string
		set        func(*config.Config)
		wantMode   string
		wantEncap  string
		wantProfil string
	}{
		{"one word: icmp", func(c *config.Config) { c.TunMode = "icmp" }, "icmp", config.EncapIPX, "icmp"},
		{"one word: gre", func(c *config.Config) { c.TunMode = "gre" }, "gre", config.EncapIPX, "gre"},
		{"one word: tcp", func(c *config.Config) { c.TunMode = "tcp" }, "tcp", config.EncapTCP, ""},
		{"the pair: ipx + ipip", func(c *config.Config) {
			c.Encapsulation, c.IpxProfile = config.EncapIPX, "ipip"
		}, "ipip", config.EncapIPX, "ipip"},
		{"the pair: tcp", func(c *config.Config) {
			c.Encapsulation, c.IpxProfile = config.EncapTCP, ""
		}, "tcp", config.EncapTCP, ""},
		{"the pair wins over one word", func(c *config.Config) {
			c.TunMode = "udp"
			c.Encapsulation, c.IpxProfile = config.EncapIPX, "gre"
		}, "gre", config.EncapIPX, "gre"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.set(c)
			if err := c.Validate(); err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if c.TunMode != tc.wantMode {
				t.Fatalf("tun_mode = %q, want %q", c.TunMode, tc.wantMode)
			}
			if c.Encapsulation != tc.wantEncap {
				t.Fatalf("encapsulation = %q, want %q", c.Encapsulation, tc.wantEncap)
			}
			if c.IpxProfile != tc.wantProfil {
				t.Fatalf("ipx_profile = %q, want %q", c.IpxProfile, tc.wantProfil)
			}
		})
	}
}

// A config written out and read back must describe the same carrier. Writing
// both namings is only safe if they cannot drift.
func TestCarrierSurvivesARoundTrip(t *testing.T) {
	for _, mode := range []string{"tcp", "udp", "icmp", "bip", "ipip", "gre"} {
		t.Run(mode, func(t *testing.T) {
			d := config.Defaults()
			c := &d
			c.Engine = config.EngineTUN
			c.Name, c.Role, c.Mode = "t", config.RoleKharej, config.ModeReverse
			c.TunnelPort, c.TunIP, c.PeerTunIP = 1234, "10.9.0.2/30", "10.9.0.1"
			c.Peer = "203.0.113.1"
			if mode == "bip" {
				c.Peer = "2001:db8::1"
			}
			c.TunMode = mode
			if err := c.Validate(); err != nil {
				t.Fatalf("rejected: %v", err)
			}

			text := c.Marshal()
			path := t.TempDir() + "/t.toml"
			if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			back, err := config.Load(path)
			if err != nil {
				t.Fatalf("re-read: %v\n%s", err, text)
			}
			if back.TunMode != mode {
				t.Fatalf("carrier came back as %q, want %q\n%s", back.TunMode, mode, text)
			}
		})
	}
}

// The ICMP message type is normally chosen by the carrier — Echo Replies, since
// no kernel answers one with a copy of the payload, falling back to Requests if
// the path drops them. An override exists only for a path that passes some other
// type, and setting one must remove the probing, which is meaningless off echo.
func TestExplicitICMPTypeReplacesTheAutomaticChoice(t *testing.T) {
	auto := &icmpLinkDialer{}
	if got := auto.pick(); len(got) != 2 {
		t.Fatalf("with no override the dialer must probe both echo directions, got %v", got)
	}

	fixed := &icmpLinkDialer{shape: shapeFrom(13, 0)} // timestamp request
	if got := fixed.pick(); len(got) != 1 {
		t.Fatalf("with an explicit type there is nothing to probe, got %v", got)
	}

	p := protoFor(config.TunModeICMP)
	sh := shapeFrom(13, 0)
	msg := appendShaped(nil, p, sh, false, 7, 1, tagToListener, 1234, []byte("frame"))
	if msg[0] != 13 || msg[1] != 0 {
		t.Fatalf("emitted type/code %d/%d, want 13/0", msg[0], msg[1])
	}
	if _, _, ok := parseEchoAnyShaped(msg, sh, false); !ok {
		t.Fatal("a message of the configured type was not accepted")
	}
	// And an echo, which is what everything else on the host sends, is not ours.
	echo := appendShaped(nil, p, icmpShape{}, true, 7, 1, tagToListener, 1234, []byte("frame"))
	if _, _, ok := parseEchoAnyShaped(echo, sh, false); ok {
		t.Fatal("an ordinary echo was accepted while an explicit type was configured")
	}
}

// Zero means "not set", not "type 0 code 0" — type 0 is Echo Reply, which is
// what the carrier already chooses, so treating it as an override would only
// disable the fallback for no reason.
func TestZeroICMPTypeMeansAutomatic(t *testing.T) {
	if shapeFrom(0, 0).set {
		t.Fatal("an unset icmp_type was read as an override")
	}
	if !shapeFrom(8, 0).set {
		t.Fatal("icmp_type = 8 was not read as an override")
	}
	if !shapeFrom(0, 5).set {
		t.Fatal("icmp_code alone was not read as an override")
	}
}

// Binding to a device is what stops a multi-homed server parsing every packet of
// that IP protocol from interfaces the peer is not on. A name that does not
// exist has to fail loudly at startup rather than silently binding nothing.
func TestBindToDeviceRejectsAnUnknownInterface(t *testing.T) {
	cfg := &config.Config{TunnelPort: 5300, Cipher: "aes-256-gcm",
		Peer: "127.0.0.1", ListenIP: "127.0.0.1", Iface: "no-such-device0"}
	if _, _, err := newIPXCarrier(config.TunModeGRE, cfg, false, cfg.Cipher, nil); err == nil {
		t.Fatal("a carrier bound to a nonexistent interface started anyway")
	}

	cfg.Iface = "lo"
	_, l, err := newIPXCarrier(config.TunModeGRE, cfg, false, cfg.Cipher, nil)
	if err != nil {
		t.Skipf("raw IP sockets unavailable: %v", err)
	}
	l.Close()
}
