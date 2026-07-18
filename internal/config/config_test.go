package config

import "testing"

func baseTUN() Config {
	c := Defaults()
	c.Name = "t"
	c.Role = RoleKharej
	c.Engine = EngineTUN
	c.Peer = "1.2.3.4"
	c.TunIP = "10.10.10.2/24"
	c.PeerTunIP = "10.10.10.1"
	return c
}

// keep an alias so existing tests below can call baseL3()
func baseL3() Config { return baseTUN() }

func TestValidateTUN(t *testing.T) {
	c := baseTUN()
	if err := c.Validate(); err != nil {
		t.Fatalf("valid tun config rejected: %v", err)
	}
}

func TestValidateTUNModes(t *testing.T) {
	for _, m := range []string{TunModeTCP, TunModeUDP, TunModeICMP, TunModeBIP} {
		c := baseTUN()
		c.TunMode = m
		if err := c.Validate(); err != nil {
			t.Fatalf("tun_mode %q rejected: %v", m, err)
		}
	}
	c := baseTUN()
	c.TunMode = "wireguard"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for invalid tun_mode")
	}
}

func baseSPF() Config {
	c := Defaults()
	c.Name = "s"
	c.Role = RoleKharej
	c.Engine = EngineSPF
	c.Peer = "203.0.113.10"
	c.TunIP = "10.10.10.2/24"
	c.PeerTunIP = "10.10.10.1"
	c.SpfProfile = SpfProfileICMP
	c.SpoofSrcIP = "5.34.222.4"
	c.SpoofDstIP = "195.62.4.29"
	return c
}

func TestValidateSPF(t *testing.T) {
	for _, p := range []string{SpfProfileICMP, SpfProfileTCP} {
		c := baseSPF()
		c.SpfProfile = p
		if err := c.Validate(); err != nil {
			t.Fatalf("valid spf (%s) rejected: %v", p, err)
		}
	}
}

func TestValidateSPFSpoofRequired(t *testing.T) {
	c := baseSPF()
	c.SpoofSrcIP = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: spoof_src_ip required")
	}
	c = baseSPF()
	c.SpoofDstIP = c.SpoofSrcIP // equal
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: spoof src == dst")
	}
	c = baseSPF()
	c.SpfProfile = "quic"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: invalid spf_profile")
	}
}

// iranTUN is an Iran-side (entry) TUN fixture — the side that owns forwards.
func iranTUN() Config {
	c := baseTUN()
	c.Role = RoleIran
	c.Peer = "" // the entry side listens; it does not dial
	c.TunIP = "10.10.10.1/24"
	c.PeerTunIP = "10.10.10.2"
	return c
}

func TestValidateL3Forwards(t *testing.T) {
	// A valid forward on an Iran TUN tunnel with a peer_tun_ip target is accepted.
	c := iranTUN()
	c.Forwards = []string{"443", "8000=9000", "200-202"}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid L3 forwards rejected: %v", err)
	}
	// SPF forwards are validated the same way (shared validateTUN path).
	s := baseSPF()
	s.Role = RoleIran
	s.Peer = ""
	s.TunIP = "10.10.10.1/24"
	s.PeerTunIP = "10.10.10.2"
	s.Forwards = []string{"51820"}
	if err := s.Validate(); err != nil {
		t.Fatalf("valid SPF forward rejected: %v", err)
	}
}

func TestValidateForwardsRejectedOnForeign(t *testing.T) {
	c := baseTUN() // role = kharej
	c.Forwards = []string{"443"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: forwards not allowed on the foreign (kharej) side")
	}
}

func TestValidateL3ForwardsRequirePeerTunIP(t *testing.T) {
	c := iranTUN()
	c.PeerTunIP = ""
	c.Forwards = []string{"443"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: L3 forwarding requires peer_tun_ip")
	}
}

func TestValidateL3ForwardsRejectBadSpec(t *testing.T) {
	c := iranTUN()
	c.Forwards = []string{"70000"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for out-of-range forward port")
	}
}

func TestUsesL3(t *testing.T) {
	spf, tun := baseSPF(), baseTUN()
	if !spf.UsesL3() || !tun.UsesL3() {
		t.Fatal("SPF and TUN should use the L3 data plane")
	}
	c := Defaults()
	c.Engine = EngineMux
	if c.UsesL3() {
		t.Fatal("mux should not use L3")
	}
}

func TestDirectModeRejected(t *testing.T) {
	c := baseTUN()
	c.Mode = "direct"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: direct mode was removed")
	}
}

func TestValidateTUNRequiresPrefix(t *testing.T) {
	c := baseTUN()
	c.TunIP = "10.10.10.2"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for tun_ip without prefix length")
	}
}

func TestValidateTUNRequiresTunIP(t *testing.T) {
	c := baseTUN()
	c.TunIP = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing tun_ip")
	}
}

func TestValidateTUNPeerSubnet(t *testing.T) {
	c := baseTUN()
	c.PeerTunIP = "192.168.9.9" // outside 10.10.10.0/24
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: peer_tun_ip outside tunnel subnet")
	}
	c = baseTUN()
	c.PeerTunIP = "10.10.10.2" // equal to tun_ip
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: peer_tun_ip equal to tun_ip")
	}
	c = baseTUN()
	c.PeerTunIP = "not-an-ip"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: peer_tun_ip invalid")
	}
}

func TestValidateTUNIPv6(t *testing.T) {
	c := baseTUN()
	c.TunIP6 = "fd00::2/64"
	if err := c.Validate(); err != nil {
		t.Fatalf("valid tun_ip6 rejected: %v", err)
	}
	c.TunIP6 = "10.0.0.1/24" // not IPv6
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: tun_ip6 must be IPv6")
	}
}

func TestEngineL3IsTUNAlias(t *testing.T) {
	c := baseTUN()
	c.Engine = EngineL3
	if !c.IsTUN() {
		t.Fatal("l3 should be recognised as the TUN engine")
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("l3 alias rejected: %v", err)
	}
}

func TestValidateHeartbeatOrdering(t *testing.T) {
	c := baseL3()
	c.HeartbeatInterval = 30
	c.HeartbeatTimeout = 10
	if err := c.Validate(); err == nil {
		t.Fatal("expected error when heartbeat_timeout <= heartbeat_interval")
	}
}

func TestValidateMuxEngine(t *testing.T) {
	c := Defaults()
	c.Name = "m"
	c.Role = RoleIran
	c.Mode = ModeReverse
	c.Engine = EngineMux
	c.TunnelPort = 443
	c.Forwards = []string{"8443", "2052-2058"}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid mux config rejected: %v", err)
	}
}

func TestValidateRejectsHealthPortCollision(t *testing.T) {
	c := Defaults()
	c.Name = "t"
	c.Role = RoleKharej
	c.Engine = EngineMux
	c.Peer = "1.2.3.4"
	c.TunnelPort = 1234
	c.HealthPort = 1234 // same as tunnel port -> must be rejected
	if err := c.Validate(); err == nil {
		t.Fatal("expected error when health_port == listen_port")
	}
}

func TestDefaultsAreSane(t *testing.T) {
	d := Defaults()
	if d.Engine != EngineMux {
		t.Errorf("default engine should be mux (TCP Reverse), got %q", d.Engine)
	}
	if d.TunnelPort != 1234 {
		t.Errorf("default tunnel port should be 1234, got %d", d.TunnelPort)
	}
	if d.HealthPort == d.TunnelPort {
		t.Errorf("default health port %d collides with tunnel port", d.HealthPort)
	}
	if d.TunIface != "emergency-tun" {
		t.Errorf("default interface should be emergency-tun, got %q", d.TunIface)
	}
	if len(d.TunIface) > 15 {
		t.Errorf("interface name %q exceeds the 15-char kernel limit", d.TunIface)
	}
	// Pool default must match the panel/examples (4) so a hand-written peer that
	// omits `pool` does not silently mismatch and blackhole TUN flows.
	if d.Pool != 4 {
		t.Errorf("default pool should be 4 (matches panel/examples), got %d", d.Pool)
	}
	if d.ExitHost != "127.0.0.1" {
		t.Errorf("default exit_host should be 127.0.0.1, got %q", d.ExitHost)
	}
}

func TestValidateHeartbeatEffective(t *testing.T) {
	// interval set high with timeout left at 0 (defaults to 25) must be rejected —
	// otherwise effective timeout 25 <= interval 30 tears links down immediately.
	c := baseTUN()
	c.HeartbeatInterval = 30
	c.HeartbeatTimeout = 0
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: effective heartbeat_timeout(25) <= interval(30)")
	}
	// The defaults (10/25) are valid.
	c = baseTUN()
	c.HeartbeatInterval, c.HeartbeatTimeout = 0, 0
	if err := c.Validate(); err != nil {
		t.Fatalf("default heartbeat should be valid: %v", err)
	}
	// A sane explicit pair is valid.
	c = baseTUN()
	c.HeartbeatInterval, c.HeartbeatTimeout = 30, 75
	if err := c.Validate(); err != nil {
		t.Fatalf("30/75 heartbeat should be valid: %v", err)
	}
	// Applies to the mux engine too (shares the fields).
	m := baseTUN()
	m.Engine = EngineMux
	m.TunIP, m.PeerTunIP = "", ""
	m.Role = RoleIran
	m.Peer = ""
	m.Forwards = []string{"443"}
	m.HeartbeatInterval, m.HeartbeatTimeout = 40, 20
	if err := m.Validate(); err == nil {
		t.Fatal("expected error: mux heartbeat 20 <= 40")
	}
}

func TestValidateRejectsUnknownEngine(t *testing.T) {
	c := baseL3()
	c.Engine = "nope"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for unknown engine")
	}
}

func TestValidateL4ForwardCollision(t *testing.T) {
	c := Defaults()
	c.Name = "t"
	c.Role = RoleIran
	c.Mode = ModeReverse // Iran is the listener, binds listen_port
	c.TunnelPort = 443
	c.Forwards = []string{"443"} // collides with the tunnel port
	if err := c.Validate(); err == nil {
		t.Fatal("expected forward/listen_port collision error")
	}
}

func TestForwardParsing(t *testing.T) {
	cases := map[string]struct {
		start, end, remote int
		pp                 bool
		ll                 bool
	}{
		"2096":         {2096, 2096, 2096, false, false},
		"8000=9000":    {8000, 8000, 9000, false, false},
		"200-203":      {200, 203, 200, false, false},
		"2096@pp":      {2096, 2096, 2096, true, false},
		"8000=9000@pp": {8000, 8000, 9000, true, false},
		"27015@ll":     {27015, 27015, 27015, false, true}, // gaming/interactive
		"443@pp@ll":    {443, 443, 443, true, true},        // combined flags
		"443@ll@pp":    {443, 443, 443, true, true},        // order-independent
	}
	for spec, want := range cases {
		f, err := ParseForward(spec, false)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if f.ListenStart != want.start || f.ListenEnd != want.end || f.RemoteBase != want.remote || f.ProxyProto != want.pp || f.LowLatency != want.ll {
			t.Errorf("%s: got %+v want %+v", spec, f, want)
		}
	}
	if _, err := ParseForward("443@bogus", false); err == nil {
		t.Error("expected error for unknown flag")
	}
}

func TestTOMLRoundTrip(t *testing.T) {
	c := baseL3()
	c.HeartbeatInterval = 10
	c.HeartbeatTimeout = 25
	c.SoSndbuf = 1048576
	out := c.Marshal()

	got := Defaults()
	if err := unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Engine != EngineTUN || got.TunIP != c.TunIP || got.SoSndbuf != c.SoSndbuf ||
		got.HeartbeatTimeout != c.HeartbeatTimeout || got.Peer != c.Peer ||
		got.PeerTunIP != c.PeerTunIP {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}
