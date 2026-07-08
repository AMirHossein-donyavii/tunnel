package config

import "testing"

const testPSK = "VOyBVKjPzJcKPEeTBvHiAIFWSm7iIBCfvYxqTbCRL+8="

func baseL3() Config {
	c := Defaults()
	c.Name = "t"
	c.Role = RoleKharej
	c.Engine = EngineL3
	c.Peer = "1.2.3.4"
	c.TunIP = "10.20.0.2/24"
	c.PSK = testPSK
	return c
}

func TestValidateL3(t *testing.T) {
	c := baseL3()
	if err := c.Validate(); err != nil {
		t.Fatalf("valid l3 config rejected: %v", err)
	}
}

func TestValidateL3RequiresPrefix(t *testing.T) {
	c := baseL3()
	c.TunIP = "10.20.0.2"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for tun_ip without prefix length")
	}
}

func TestValidateL3RequiresTunIP(t *testing.T) {
	c := baseL3()
	c.TunIP = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing tun_ip")
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

func TestValidateL4ForwardCollision(t *testing.T) {
	c := Defaults()
	c.Name = "t"
	c.Role = RoleIran
	c.Mode = ModeReverse // Iran is the listener, binds listen_port
	c.PSK = testPSK
	c.ListenPort = 443
	c.Forwards = []string{"443"} // collides with the tunnel port
	if err := c.Validate(); err == nil {
		t.Fatal("expected forward/listen_port collision error")
	}
}

func TestForwardParsing(t *testing.T) {
	cases := map[string]struct {
		start, end, remote int
		pp                 bool
	}{
		"2096":       {2096, 2096, 2096, false},
		"8000=9000":  {8000, 8000, 9000, false},
		"200-203":    {200, 203, 200, false},
		"2096@pp":    {2096, 2096, 2096, true},
		"8000=9000@pp": {8000, 8000, 9000, true},
	}
	for spec, want := range cases {
		f, err := ParseForward(spec, false)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if f.ListenStart != want.start || f.ListenEnd != want.end || f.RemoteBase != want.remote || f.ProxyProto != want.pp {
			t.Errorf("%s: got %+v want %+v", spec, f, want)
		}
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
	if got.Engine != EngineL3 || got.TunIP != c.TunIP || got.SoSndbuf != c.SoSndbuf ||
		got.HeartbeatTimeout != c.HeartbeatTimeout || got.Peer != c.Peer {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}
