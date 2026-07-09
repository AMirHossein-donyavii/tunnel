package firewall

import (
	"strings"
	"testing"

	"github.com/emergency-tunnel/et/internal/config"
)

func baseL3() *config.Config {
	return &config.Config{
		Name:      "vpn1",
		Engine:    config.EngineTUN,
		PeerTunIP: "10.10.10.2",
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
