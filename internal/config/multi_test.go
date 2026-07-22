package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- ScanDir / LoadRelaxed ---------------------------------------------------

// TestScanDirIsTolerant verifies the host inventory scan keeps going past files
// that would fail full validation — an invalid or foreign config must still
// contribute its claimed ports so a new tunnel avoids them.
func TestScanDirIsTolerant(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Valid.
	write("a.toml", "name=\"a\"\nrole=\"iran\"\nengine=\"mux\"\ntunnel_port=1234\nhealth_port=9090\nforwards=[\"443\"]\n")
	// Would FAIL Validate (iran mux with no forwards) but still claims ports.
	write("b.toml", "name=\"b\"\nrole=\"iran\"\nengine=\"mux\"\ntunnel_port=1235\nhealth_port=9091\n")
	// Not a config at all.
	write("notes.txt", "ignore me")

	got := ScanDir(dir)
	if len(got) != 2 {
		t.Fatalf("ScanDir returned %d configs, want 2 (invalid ones still count)", len(got))
	}
	inv := TakeInventory(got)
	for _, p := range []int{1234, 1235} {
		if _, ok := inv.TunnelPorts[p]; !ok {
			t.Errorf("port %d not recorded in the inventory", p)
		}
	}
	// A new tunnel must skip both claimed ports.
	if s := SuggestDefaults(got, RoleIran); s.TunnelPort == 1234 || s.TunnelPort == 1235 {
		t.Errorf("suggested a claimed tunnel_port %d", s.TunnelPort)
	}
}

func TestLoadRelaxedFallsBackToFileName(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "unnamed.toml")
	if err := os.WriteFile(p, []byte("role=\"iran\"\nengine=\"mux\"\ntunnel_port=1234\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadRelaxed(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "unnamed" {
		t.Errorf("name=%q, want the file stem %q", c.Name, "unnamed")
	}
}

func TestScanDirMissingDirIsEmpty(t *testing.T) {
	if got := ScanDir(filepath.Join(t.TempDir(), "does-not-exist")); got != nil {
		t.Errorf("missing dir should scan to nil, got %v", got)
	}
}

// --- SuggestDefaults ---------------------------------------------------------

// TestSuggestDefaultsFirstTunnelIsUnchanged pins backward compatibility: on a
// fresh host the suggestion must be exactly today's documented defaults.
func TestSuggestDefaultsFirstTunnelIsUnchanged(t *testing.T) {
	d := Defaults()
	s := SuggestDefaults(nil, RoleIran)
	if s.TunnelPort != d.TunnelPort {
		t.Errorf("tunnel_port=%d, want the stock %d", s.TunnelPort, d.TunnelPort)
	}
	if s.HealthPort != d.HealthPort {
		t.Errorf("health_port=%d, want the stock %d", s.HealthPort, d.HealthPort)
	}
	if s.TunIface != d.TunIface {
		t.Errorf("tun_iface=%q, want the stock %q", s.TunIface, d.TunIface)
	}
	if s.TunIP != "10.10.10.1/24" || s.PeerTunIP != "10.10.10.2" {
		t.Errorf("first tunnel addressing = %s / %s, want 10.10.10.1/24 / 10.10.10.2", s.TunIP, s.PeerTunIP)
	}
	if s.SpoofSrcIP != "195.62.4.29" || s.SpoofDstIP != "5.34.222.4" {
		t.Errorf("first SPF spoof pair = %s/%s, want the stock 195.62.4.29/5.34.222.4", s.SpoofSrcIP, s.SpoofDstIP)
	}
}

func TestSuggestDefaultsRoleMirroring(t *testing.T) {
	k := SuggestDefaults(nil, RoleKharej)
	if k.TunIP != "10.10.10.2/24" || k.PeerTunIP != "10.10.10.1" {
		t.Errorf("kharej addressing = %s / %s, want 10.10.10.2/24 / 10.10.10.1", k.TunIP, k.PeerTunIP)
	}
	// The spoof pair is the mirror of the Iran side.
	if k.SpoofSrcIP != "5.34.222.4" || k.SpoofDstIP != "195.62.4.29" {
		t.Errorf("kharej spoof pair = %s/%s, want mirrored", k.SpoofSrcIP, k.SpoofDstIP)
	}
}

// TestSuggestDefaultsStepsAwayFromExisting is the headline requirement: a second
// tunnel must not reuse the first tunnel's subnet, ports, or interface.
func TestSuggestDefaultsStepsAwayFromExisting(t *testing.T) {
	first := &Config{
		Name: "t1", Role: RoleIran, Engine: EngineTUN,
		TunnelPort: 1234, HealthPort: 9090, TunIface: "emergency-tun",
		TunIP: "10.10.10.1/24", PeerTunIP: "10.10.10.2",
	}
	s := SuggestDefaults([]*Config{first}, RoleIran)
	if s.TunnelPort == 1234 {
		t.Error("second tunnel reused tunnel_port 1234")
	}
	if s.HealthPort == 9090 {
		t.Error("second tunnel reused health_port 9090")
	}
	if s.TunIface == "emergency-tun" {
		t.Error("second tunnel reused the interface name")
	}
	if s.TunIP != "10.10.20.1/24" || s.PeerTunIP != "10.10.20.2" {
		t.Errorf("second tunnel subnet = %s / %s, want 10.10.20.1/24 / 10.10.20.2", s.TunIP, s.PeerTunIP)
	}
	if len(s.TunIface) > maxIfaceLen {
		t.Errorf("generated iface %q exceeds the %d-char kernel limit", s.TunIface, maxIfaceLen)
	}
}

// TestSuggestDefaultsFourTunnels walks the user's scenario: 4 tunnels on one
// server, every one isolated.
func TestSuggestDefaultsFourTunnels(t *testing.T) {
	var have []*Config
	seenSubnet := map[string]bool{}
	seenPort := map[int]bool{}
	seenHealth := map[int]bool{}
	seenIface := map[string]bool{}
	wantOctets := []string{"10.10.10.1/24", "10.10.20.1/24", "10.10.30.1/24", "10.10.40.1/24"}

	for i := 0; i < 4; i++ {
		s := SuggestDefaults(have, RoleIran)
		if s.TunIP != wantOctets[i] {
			t.Fatalf("tunnel %d subnet = %s, want %s", i+1, s.TunIP, wantOctets[i])
		}
		if seenSubnet[s.TunIP] || seenPort[s.TunnelPort] || seenHealth[s.HealthPort] || seenIface[s.TunIface] {
			t.Fatalf("tunnel %d collides with an earlier one: %+v", i+1, s)
		}
		seenSubnet[s.TunIP], seenPort[s.TunnelPort], seenHealth[s.HealthPort], seenIface[s.TunIface] = true, true, true, true
		have = append(have, &Config{
			Name: s.Name, Role: RoleIran, Engine: EngineTUN,
			TunnelPort: s.TunnelPort, HealthPort: s.HealthPort,
			TunIface: s.TunIface, TunIP: s.TunIP, PeerTunIP: s.PeerTunIP,
		})
	}
	// And none of the four configs conflict with each other.
	for i, c := range have {
		if cs := FindConflicts(c, have); len(cs) != 0 {
			t.Fatalf("tunnel %d reports conflicts: %v", i+1, cs)
		}
	}
}

func TestSuggestDefaultsDistinctSpoofPairForSecondSPF(t *testing.T) {
	first := &Config{
		Name: "s1", Role: RoleIran, Engine: EngineSPF,
		SpoofSrcIP: "195.62.4.29", SpoofDstIP: "5.34.222.4",
	}
	s := SuggestDefaults([]*Config{first}, RoleIran)
	if s.SpoofDstIP == "5.34.222.4" {
		t.Error("second SPF tunnel reused spoof_dst_ip — the two listeners would cross-talk")
	}
	if s.SpoofSrcIP == "195.62.4.29" {
		t.Error("second SPF tunnel reused spoof_src_ip")
	}
}

func TestNextFreeIfaceRespectsKernelLimit(t *testing.T) {
	used := map[string]string{"emergency-tun": "t1"}
	for i := 2; i < 20; i++ {
		got := nextFreeIface("emergency-tun", used)
		if len(got) > maxIfaceLen {
			t.Fatalf("generated %q (%d chars), exceeds %d", got, len(got), maxIfaceLen)
		}
		if _, dup := used[got]; dup {
			t.Fatalf("generated a name already in use: %q", got)
		}
		used[got] = "x"
	}
}

// --- FindConflicts -----------------------------------------------------------

func TestFindConflictsDetectsEachResource(t *testing.T) {
	existing := &Config{
		Name: "t1", Role: RoleIran, Engine: EngineTUN,
		TunnelPort: 1234, HealthPort: 9090, TunIface: "emergency-tun",
		TunIP: "10.10.10.1/24", PeerTunIP: "10.10.10.2",
		Forwards: []string{"443"},
	}
	cand := &Config{
		Name: "t2", Role: RoleIran, Engine: EngineTUN,
		TunnelPort: 1234, HealthPort: 9090, TunIface: "emergency-tun",
		TunIP: "10.10.10.1/24", PeerTunIP: "10.10.10.2",
		Forwards: []string{"443"},
	}
	cs := FindConflicts(cand, []*Config{existing})
	want := []string{"tunnel_port", "health_port", "tun_iface", "tun_ip", "forward port"}
	for _, w := range want {
		found := false
		for _, c := range cs {
			if c.Resource == w {
				found = true
			}
		}
		if !found {
			t.Errorf("expected a %q conflict; got %v", w, cs)
		}
	}
}

func TestFindConflictsIgnoresSelf(t *testing.T) {
	c := &Config{
		Name: "t1", Role: RoleIran, Engine: EngineTUN,
		TunnelPort: 1234, HealthPort: 9090, TunIface: "emergency-tun", TunIP: "10.10.10.1/24",
	}
	if cs := FindConflicts(c, []*Config{c}); len(cs) != 0 {
		t.Fatalf("a config must never conflict with itself, got %v", cs)
	}
}

func TestFindConflictsCleanWhenIsolated(t *testing.T) {
	a := &Config{
		Name: "t1", Role: RoleIran, Engine: EngineTUN,
		TunnelPort: 1234, HealthPort: 9090, TunIface: "emergency-tun",
		TunIP: "10.10.10.1/24", Forwards: []string{"443"},
	}
	b := &Config{
		Name: "t2", Role: RoleIran, Engine: EngineTUN,
		TunnelPort: 1235, HealthPort: 9091, TunIface: "emergency-tun2",
		TunIP: "10.10.20.1/24", Forwards: []string{"8443"},
	}
	if cs := FindConflicts(b, []*Config{a}); len(cs) != 0 {
		t.Fatalf("properly isolated tunnels must not conflict, got %v", cs)
	}
}

// Two dialers (Kharej) may share a tunnel_port only if they aim at different
// peers — same peer + same port means they'd join the same remote tunnel.
func TestFindConflictsDialerSemantics(t *testing.T) {
	a := &Config{Name: "k1", Role: RoleKharej, Engine: EngineMux, TunnelPort: 1234, Peer: "203.0.113.1"}
	sameePeer := &Config{Name: "k2", Role: RoleKharej, Engine: EngineMux, TunnelPort: 1234, Peer: "203.0.113.1"}
	otherPeer := &Config{Name: "k3", Role: RoleKharej, Engine: EngineMux, TunnelPort: 1234, Peer: "203.0.113.9"}

	if cs := FindConflicts(sameePeer, []*Config{a}); len(cs) == 0 {
		t.Error("same peer + same tunnel_port on two dialers should conflict")
	}
	if cs := FindConflicts(otherPeer, []*Config{a}); len(cs) != 0 {
		t.Errorf("different peers may reuse a tunnel_port on the dialing side, got %v", cs)
	}
}

func TestFindConflictsSPFSpoofDst(t *testing.T) {
	a := &Config{Name: "s1", Role: RoleIran, Engine: EngineSPF, TunnelPort: 1234, SpoofSrcIP: "1.1.1.1", SpoofDstIP: "2.2.2.2"}
	b := &Config{Name: "s2", Role: RoleIran, Engine: EngineSPF, TunnelPort: 1235, SpoofSrcIP: "3.3.3.3", SpoofDstIP: "2.2.2.2"}
	cs := FindConflicts(b, []*Config{a})
	found := false
	for _, c := range cs {
		if c.Resource == "spoof_dst_ip" {
			found = true
		}
	}
	if !found {
		t.Errorf("two SPF tunnels sharing spoof_dst_ip must conflict, got %v", cs)
	}
}

func TestConflictStringIsActionable(t *testing.T) {
	c := Conflict{Resource: "tun_iface", Value: "emergency-tun", With: "t1", Detail: "same device"}
	s := c.String()
	for _, want := range []string{"tun_iface", "emergency-tun", "t1", "same device"} {
		if !strings.Contains(s, want) {
			t.Errorf("conflict string %q missing %q", s, want)
		}
	}
}
