package firewall

import (
	"strings"
	"testing"

	"github.com/emergency-tunnel/et/internal/config"
)

func baseL3() *config.Config {
	return &config.Config{
		Name:      "vpn1",
		Role:      config.RoleIran, // forwards live on the entry side only
		Engine:    config.EngineTUN,
		PeerTunIP: "10.10.10.2",
	}
}

func TestPlanDisabledOnForeign(t *testing.T) {
	c := baseL3()
	c.Role = config.RoleKharej
	c.Forwards = []string{"443"}
	rules, err := Plan(c)
	if err != nil || rules != nil {
		t.Fatalf("foreign side must plan no rules; got %v %v", rules, err)
	}
	if Enabled(c) {
		t.Fatal("Enabled must be false on the foreign side")
	}
}

func TestPlanEmpty(t *testing.T) {
	rules, err := Plan(baseL3())
	if err != nil || rules != nil {
		t.Fatalf("no forwards should yield (nil,nil); got %v %v", rules, err)
	}
}

func TestPlanSinglePortTCPandUDP(t *testing.T) {
	c := baseL3()
	c.Forwards = []string{"443"}
	rules, err := Plan(c)
	if err != nil {
		t.Fatal(err)
	}
	// One port -> tcp + udp.
	if len(rules) != 2 {
		t.Fatalf("want 2 rules (tcp+udp), got %d: %+v", len(rules), rules)
	}
	protos := map[string]bool{}
	for _, r := range rules {
		protos[r.Proto] = true
		if r.ListenPort != 443 || r.DestPort != 443 || r.Dest != "10.10.10.2" {
			t.Fatalf("unexpected rule: %+v", r)
		}
	}
	if !protos["tcp"] || !protos["udp"] {
		t.Fatalf("want both tcp and udp, got %v", protos)
	}
}

func TestPlanMappingAndRange(t *testing.T) {
	c := baseL3()
	c.Forwards = []string{"8000=9000", "200-202"}
	rules, err := Plan(c)
	if err != nil {
		t.Fatal(err)
	}
	// mapping: 1 port x2 protos = 2; range 200..202: 3 ports x2 = 6; total 8.
	if len(rules) != 8 {
		t.Fatalf("want 8 rules, got %d", len(rules))
	}
	var sawMap bool
	for _, r := range rules {
		if r.ListenPort == 8000 {
			sawMap = true
			if r.DestPort != 9000 {
				t.Fatalf("mapping 8000=9000 should target 9000, got %d", r.DestPort)
			}
		}
		if r.ListenPort >= 200 && r.ListenPort <= 202 && r.DestPort != r.ListenPort {
			t.Fatalf("range port %d should map to itself, got %d", r.ListenPort, r.DestPort)
		}
	}
	if !sawMap {
		t.Fatal("mapping rule missing")
	}
}

func TestPlanRequiresPeerTunIP(t *testing.T) {
	c := baseL3()
	c.PeerTunIP = ""
	c.Forwards = []string{"443"}
	if _, err := Plan(c); err == nil {
		t.Fatal("expected error when peer_tun_ip is missing")
	}
	c.PeerTunIP = "not-an-ip"
	if _, err := Plan(c); err == nil {
		t.Fatal("expected error when peer_tun_ip is malformed")
	}
}

func TestPlanRejectsBadPort(t *testing.T) {
	c := baseL3()
	c.Forwards = []string{"70000"}
	if _, err := Plan(c); err == nil {
		t.Fatal("expected error for out-of-range port")
	}
}

func TestTag(t *testing.T) {
	if Tag("vpn1") != "et:vpn1" {
		t.Fatalf("unexpected tag %q", Tag("vpn1"))
	}
}

func TestRulesForSpecs(t *testing.T) {
	r := Rule{Proto: "tcp", ListenPort: 443, Dest: "10.10.10.2", DestPort: 8443}
	rules := rulesFor(r, "emergency-tun", "et:vpn1")
	if len(rules) != 4 {
		t.Fatalf("want 4 iptables rules per forward, got %d", len(rules))
	}
	joined := make([]string, len(rules))
	for i, ir := range rules {
		joined[i] = ir.table + " " + ir.chain + " " + strings.Join(ir.args, " ")
	}
	want := []string{
		"nat PREROUTING -p tcp --dport 443 -m comment --comment et:vpn1 -j DNAT --to-destination 10.10.10.2:8443",
		"filter FORWARD -p tcp -d 10.10.10.2 --dport 8443 -m comment --comment et:vpn1 -j ACCEPT",
		"filter FORWARD -p tcp -s 10.10.10.2 --sport 8443 -m comment --comment et:vpn1 -j ACCEPT",
		"nat POSTROUTING -o emergency-tun -p tcp -d 10.10.10.2 --dport 8443 -m comment --comment et:vpn1 -j MASQUERADE",
	}
	for i := range want {
		if joined[i] != want[i] {
			t.Errorf("rule %d:\n got  %q\n want %q", i, joined[i], want[i])
		}
	}
}

func TestMSSClampRule(t *testing.T) {
	ir := mssClampRule("emergency-tun", "et:vpn1")
	got := ir.table + " " + ir.chain + " " + strings.Join(ir.args, " ")
	want := "mangle FORWARD -o emergency-tun -p tcp --tcp-flags SYN,RST SYN -m comment --comment et:vpn1 -j TCPMSS --clamp-mss-to-pmtu"
	if got != want {
		t.Fatalf("\n got  %q\n want %q", got, want)
	}
}

// The SPF tcp carrier puts the link inside bare TCP segments that no socket is
// listening for, so the kernel resets them and the carrier dies at its first
// packet. The console used to print an iptables command and trust the operator
// to run it on both servers; anyone who did not got a tunnel that handshaked
// forever and moved nothing. The tunnel installs the rule itself now.
func TestSPFTCPGetsRSTSuppression(t *testing.T) {
	c := config.Defaults()
	c.Name, c.Engine, c.SpfProfile = "spf1", config.EngineSPF, config.SpfProfileTCP
	c.TunnelPort = 4321

	if !SPFNeedsRSTDrop(&c) {
		t.Fatal("the SPF tcp carrier needs its resets suppressed")
	}

	rules := spfRSTRules(c.TunnelPort, Tag(c.Name))
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2 — the tunnel port is the source on one side "+
			"and the destination on the other", len(rules))
	}
	var sawSport, sawDport bool
	for _, r := range rules {
		if r.table != "filter" || r.chain != "OUTPUT" {
			t.Fatalf("rule lands in %s/%s; the kernel's resets leave through filter/OUTPUT", r.table, r.chain)
		}
		joined := strings.Join(r.args, " ")
		// Narrow: only resets, only this port, and tagged for a clean teardown.
		for _, want := range []string{"--tcp-flags RST RST", "-j DROP", "4321", Tag(c.Name)} {
			if !strings.Contains(joined, want) {
				t.Fatalf("rule %q is missing %q", joined, want)
			}
		}
		sawSport = sawSport || strings.Contains(joined, "--sport")
		sawDport = sawDport || strings.Contains(joined, "--dport")
	}
	if !sawSport || !sawDport {
		t.Fatal("both directions must be covered: the listener's reset carries the " +
			"tunnel port as its source, the dialer's as its destination")
	}
}

// Only that one carrier. Every other protocol's traffic belongs to a real
// socket, and dropping resets for them would hide genuine connection failures.
func TestOtherCarriersGetNoRSTSuppression(t *testing.T) {
	for _, tc := range []struct {
		name    string
		engine  string
		profile string
	}{
		{"spf icmp", config.EngineSPF, config.SpfProfileICMP},
		{"tun", config.EngineTUN, ""},
		{"mux", config.EngineMux, ""},
		{"direct", config.EngineDirect, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := config.Defaults()
			c.Engine, c.SpfProfile = tc.engine, tc.profile
			if SPFNeedsRSTDrop(&c) {
				t.Fatal("resets suppressed for a carrier whose traffic has a real socket")
			}
		})
	}
}
