// Package firewall manages the kernel port-forwarding rules for the L3 (TUN and
// SPF) engines. A tunnel that forwards a VPN/service port gets iptables rules
// that DNAT connections arriving on the local listen port across the tunnel to
// the peer's tunnel IP, plus the matching FORWARD accepts and a MASQUERADE so
// return traffic comes back through the tunnel.
//
// The rule set is a pure function of the config (see Plan), so applying it is
// idempotent and removing it is deterministic — the same tunnel always resolves
// to the same rules, tagged with a per-tunnel comment for a safe sweep-based
// teardown. The platform-specific apply/remove live in firewall_linux.go; other
// platforms get no-ops so the rest of the daemon still builds and tests.
package firewall

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/emergency-tunnel/et/internal/config"
)

// Rule is one resolved forward: accept connections to ListenPort on this host
// and DNAT them across the tunnel to Dest:DestPort. Every forward is planned for
// both TCP and UDP so it covers the full range of VPN traffic (WireGuard/UDP,
// OpenVPN/TCP+UDP), game servers and streaming without the user having to know
// the transport.
type Rule struct {
	Proto      string // "tcp" | "udp"
	ListenPort int    // local port users connect to
	Dest       string // peer's tunnel IP (DNAT target)
	DestPort   int    // port on the peer
}

// protos is the fixed set of L4 protocols each forward is applied to.
var protos = [...]string{"tcp", "udp"}

// Plan resolves a tunnel's forward specs into concrete DNAT rules aimed at the
// peer's tunnel IP. It returns (nil, nil) when the tunnel forwards nothing, and
// an error when forwards are configured but the target (peer_tun_ip) is missing
// or malformed. Plan is platform-neutral and unit-tested.
func Plan(cfg *config.Config) ([]Rule, error) {
	if !Enabled(cfg) {
		return nil, nil
	}
	dest := strings.TrimSpace(cfg.PeerTunIP)
	if ip := net.ParseIP(dest); ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("port forwarding needs a valid IPv4 peer_tun_ip (got %q)", cfg.PeerTunIP)
	}
	var rules []Rule
	for _, spec := range cfg.Forwards {
		f, err := config.ParseForward(spec, false)
		if err != nil {
			return nil, fmt.Errorf("forward %q: %w", spec, err)
		}
		for lp := f.ListenStart; lp <= f.ListenEnd; lp++ {
			rp := f.RemoteFor(lp)
			for _, proto := range protos {
				rules = append(rules, Rule{Proto: proto, ListenPort: lp, Dest: dest, DestPort: rp})
			}
		}
	}
	return rules, nil
}

// iptRule is one concrete iptables rule: a table, a chain, and the match/target
// arguments (already including the comment match). Building it is pure string
// assembly with no platform dependency, so it lives here and is unit-tested.
type iptRule struct {
	table string
	chain string
	args  []string
}

// rulesFor expands one forward into its four iptables rules: DNAT the inbound
// port to the peer over the tunnel, ACCEPT the forward and its return in the
// FORWARD chain (so it works even when the default FORWARD policy is DROP), and
// MASQUERADE out the tunnel interface so replies route back through us.
func rulesFor(r Rule, iface, tag string) []iptRule {
	dst := r.Dest
	dp := strconv.Itoa(r.DestPort)
	lp := strconv.Itoa(r.ListenPort)
	comment := []string{"-m", "comment", "--comment", tag}
	join := func(parts ...[]string) []string {
		var out []string
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	return []iptRule{
		{"nat", "PREROUTING", join(
			[]string{"-p", r.Proto, "--dport", lp}, comment,
			[]string{"-j", "DNAT", "--to-destination", dst + ":" + dp})},
		{"filter", "FORWARD", join(
			[]string{"-p", r.Proto, "-d", dst, "--dport", dp}, comment,
			[]string{"-j", "ACCEPT"})},
		{"filter", "FORWARD", join(
			[]string{"-p", r.Proto, "-s", dst, "--sport", dp}, comment,
			[]string{"-j", "ACCEPT"})},
		{"nat", "POSTROUTING", join(
			[]string{"-o", iface, "-p", r.Proto, "-d", dst, "--dport", dp}, comment,
			[]string{"-j", "MASQUERADE"})},
	}
}

// mssClampRule clamps the TCP MSS of forwarded connections entering the tunnel
// to the path MTU. Without it, a client negotiating a 1460 MSS over a 1500 MTU
// path will blackhole large segments once they hit the smaller tunnel MTU
// (DF set, no PMTUD) — the classic "SSH connects, big transfers hang" symptom.
// One rule per tunnel covers all its TCP forwards.
func mssClampRule(iface, tag string) iptRule {
	return iptRule{"mangle", "FORWARD", []string{
		"-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-m", "comment", "--comment", tag,
		"-j", "TCPMSS", "--clamp-mss-to-pmtu"}}
}

// Tag is the iptables comment stamped on every rule this tunnel owns. Teardown
// removes exactly the rules carrying this tag, so tunnels never disturb each
// other's rules or anything the operator added by hand.
func Tag(name string) string { return "et:" + name }

// Enabled reports whether this host installs forwarding rules: it has forwards
// configured AND is the Iran (entry) server. The Foreign side never binds
// client ports or installs NAT, so it is always disabled there.
func Enabled(cfg *config.Config) bool { return len(cfg.Forwards) > 0 && cfg.IsEntry() }
