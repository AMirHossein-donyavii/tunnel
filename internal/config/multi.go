package config

import (
	"fmt"
	"net"
	"strings"
)

// Multi-tunnel support: one server may host several independent tunnels at once.
// Everything a tunnel binds or names is host-global (TCP ports, the TUN device
// name, the tunnel subnet, the client-facing forward ports), so a second tunnel
// created from the stock defaults would collide with the first on every axis.
//
// This file provides the two halves of the solution, both pure and unit-tested:
//   - Inventory/SuggestDefaults: pick the next FREE value for a new tunnel, while
//     the first tunnel on a host still gets exactly today's defaults.
//   - FindConflicts: detect a clash between a candidate config and the tunnels
//     already on the host, so creation can refuse rather than fail at runtime.

// DefaultSubnetOctet is the third octet of the stock tunnel subnet (10.10.10.0/24).
// Additional tunnels step it by SubnetStride (10.10.20, 10.10.30, …).
const (
	DefaultSubnetOctet = 10
	SubnetStride       = 10
	maxIfaceLen        = 15 // Linux IFNAMSIZ-1
)

// Inventory records which host-global resources are already claimed, mapping each
// value to the tunnel that owns it (for actionable conflict messages).
type Inventory struct {
	Names        map[string]bool
	TunnelPorts  map[int]string
	HealthPorts  map[int]string
	Ifaces       map[string]string
	SubnetOctets map[int]string // third octet of a 10.10.X.0/24 tunnel subnet
	Subnets      map[string]string
	ForwardPorts map[int]string
	SpoofDsts    map[string]string
}

// TakeInventory summarises the resources claimed by the given tunnels.
func TakeInventory(existing []*Config) Inventory {
	inv := Inventory{
		Names:        map[string]bool{},
		TunnelPorts:  map[int]string{},
		HealthPorts:  map[int]string{},
		Ifaces:       map[string]string{},
		SubnetOctets: map[int]string{},
		Subnets:      map[string]string{},
		ForwardPorts: map[int]string{},
		SpoofDsts:    map[string]string{},
	}
	for _, c := range existing {
		if c == nil {
			continue
		}
		inv.Names[c.Name] = true
		if c.TunnelPort > 0 {
			inv.TunnelPorts[c.TunnelPort] = c.Name
		}
		if c.HealthPort > 0 {
			inv.HealthPorts[c.HealthPort] = c.Name
		}
		if c.UsesL3() {
			if iface := strings.TrimSpace(c.TunIface); iface != "" {
				inv.Ifaces[iface] = c.Name
			}
			if netw, ok := subnetKey(c.TunIP); ok {
				inv.Subnets[netw] = c.Name
			}
			if oct, ok := thirdOctet(c.TunIP); ok {
				inv.SubnetOctets[oct] = c.Name
			}
		}
		if c.IsSPF() {
			if d := strings.TrimSpace(c.SpoofDstIP); d != "" {
				inv.SpoofDsts[d] = c.Name
			}
		}
		for _, spec := range c.Forwards {
			f, err := ParseForward(spec, false)
			if err != nil {
				continue
			}
			for p := f.ListenStart; p <= f.ListenEnd; p++ {
				inv.ForwardPorts[p] = c.Name
			}
		}
	}
	return inv
}

// Suggestion is a set of defaults for a NEW tunnel that collide with nothing
// already on the host. On a fresh host it is byte-for-byte today's defaults.
type Suggestion struct {
	TunnelPort int    `json:"tunnel_port"`
	HealthPort int    `json:"health_port"`
	TunIface   string `json:"tun_iface"`
	TunIP      string `json:"tun_ip"`      // CIDR for THIS host's role
	PeerTunIP  string `json:"peer_tun_ip"` // the other host's address
	SpoofSrcIP string `json:"spoof_src_ip"`
	SpoofDstIP string `json:"spoof_dst_ip"`
	Subnet     string `json:"subnet"` // e.g. "10.10.20.0/24", for display
	Name       string `json:"name"`
}

// SuggestDefaults picks non-conflicting defaults for a new tunnel with the given
// role. The first tunnel on a host receives the historical defaults unchanged
// (tunnel_port 1234, health 9090, emergency-tun, 10.10.10.1/.2), so existing
// single-tunnel behaviour and documentation stay correct.
func SuggestDefaults(existing []*Config, role string) Suggestion {
	inv := TakeInventory(existing)
	d := Defaults()

	oct := nextSubnetOctet(inv)
	iranIP := fmt.Sprintf("10.10.%d.1", oct)
	kharejIP := fmt.Sprintf("10.10.%d.2", oct)

	s := Suggestion{
		TunnelPort: nextFreePort(d.TunnelPort, inv.TunnelPorts),
		HealthPort: nextFreePort(d.HealthPort, inv.HealthPorts),
		TunIface:   nextFreeIface(d.TunIface, inv.Ifaces),
		Subnet:     fmt.Sprintf("10.10.%d.0/24", oct),
		Name:       nextFreeName(inv.Names),
	}
	if role == RoleKharej {
		s.TunIP, s.PeerTunIP = kharejIP+"/24", iranIP
	} else {
		s.TunIP, s.PeerTunIP = iranIP+"/24", kharejIP
	}
	s.SpoofSrcIP, s.SpoofDstIP = nextSpoofPair(inv, role)
	return s
}

// nextFreePort returns the first unused port at or after base.
func nextFreePort(base int, used map[int]string) int {
	for p := base; p <= 65535; p++ {
		if _, taken := used[p]; !taken {
			return p
		}
	}
	return base
}

// nextFreeIface keeps the stock name for the first tunnel, then appends an index
// (emergency-tun2, emergency-tun3, …) staying within the 15-char kernel limit.
func nextFreeIface(base string, used map[string]string) string {
	if _, taken := used[base]; !taken {
		return base
	}
	for i := 2; i < 100; i++ {
		cand := fmt.Sprintf("%s%d", base, i)
		if len(cand) > maxIfaceLen {
			// Shorten the stem so the index still fits (e.g. "emergency-tu12").
			trim := len(cand) - maxIfaceLen
			if trim < len(base) {
				cand = fmt.Sprintf("%s%d", base[:len(base)-trim], i)
			}
		}
		if len(cand) > maxIfaceLen {
			continue
		}
		if _, taken := used[cand]; !taken {
			return cand
		}
	}
	return base
}

// nextSubnetOctet steps the third octet by 10 (10.10.10 → 10.10.20 → 10.10.30),
// matching the documented scheme, then falls back to single steps if those run
// out, so a host can host many tunnels before the space is exhausted.
func nextSubnetOctet(inv Inventory) int {
	for o := DefaultSubnetOctet; o <= 250; o += SubnetStride {
		if _, taken := inv.SubnetOctets[o]; !taken {
			return o
		}
	}
	for o := 1; o <= 254; o++ {
		if _, taken := inv.SubnetOctets[o]; !taken {
			return o
		}
	}
	return DefaultSubnetOctet
}

// nextFreeName suggests an unused tunnel name (tunnel1, tunnel2, …).
func nextFreeName(used map[string]bool) string {
	for i := 1; i < 1000; i++ {
		cand := fmt.Sprintf("tunnel%d", i)
		if !used[cand] {
			return cand
		}
	}
	return "tunnel"
}

// nextSpoofPair returns the SPF spoof addresses for a new tunnel. Every SPF
// listener on a host receives a copy of all matching raw packets and filters by
// the peer's spoofed SOURCE, so two SPF tunnels sharing a spoof_dst_ip would see
// each other's traffic. Later tunnels therefore get a distinct pair (the last
// octet is stepped) — no protocol change, just distinct addresses.
func nextSpoofPair(inv Inventory, role string) (src, dst string) {
	const baseIran, baseKharej = "195.62.4.29", "5.34.222.4"
	for i := 0; i < 200; i++ {
		iran, ok1 := offsetLastOctet(baseIran, i)
		kharej, ok2 := offsetLastOctet(baseKharej, i)
		if !ok1 || !ok2 {
			break
		}
		// dst is the address we expect the PEER to spoof as its source.
		if role == RoleKharej {
			src, dst = kharej, iran
		} else {
			src, dst = iran, kharej
		}
		if _, taken := inv.SpoofDsts[dst]; !taken {
			return src, dst
		}
	}
	if role == RoleKharej {
		return baseKharej, baseIran
	}
	return baseIran, baseKharej
}

// offsetLastOctet returns ip with its final octet advanced by n (1..254).
func offsetLastOctet(ip string, n int) (string, bool) {
	p := net.ParseIP(strings.TrimSpace(ip)).To4()
	if p == nil {
		return "", false
	}
	last := int(p[3]) + n
	if last < 1 || last > 254 {
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d.%d", p[0], p[1], p[2], last), true
}

// subnetKey returns the canonical network of a CIDR ("10.10.10.0/24").
func subnetKey(cidr string) (string, bool) {
	_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return "", false
	}
	return n.String(), true
}

// thirdOctet extracts X from a 10.10.X.y address (used for subnet stepping).
func thirdOctet(cidr string) (int, bool) {
	s := strings.TrimSpace(cidr)
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	p := net.ParseIP(s).To4()
	if p == nil {
		return 0, false
	}
	return int(p[2]), true
}

// Conflict is one resource clash between a candidate tunnel and an existing one.
type Conflict struct {
	Resource string `json:"resource"`
	Value    string `json:"value"`
	With     string `json:"with"`   // the other tunnel's name
	Detail   string `json:"detail"` // why it breaks
}

func (c Conflict) String() string {
	return fmt.Sprintf("%s %s conflicts with tunnel %q: %s", c.Resource, c.Value, c.With, c.Detail)
}

// FindConflicts reports every host-global resource the candidate would take from
// an existing tunnel. A config is never compared against itself (same name), so
// re-checking an already-installed tunnel is clean.
func FindConflicts(c *Config, others []*Config) []Conflict {
	var out []Conflict
	add := func(res, val, with, detail string) {
		out = append(out, Conflict{Resource: res, Value: val, With: with, Detail: detail})
	}
	for _, o := range others {
		if o == nil || o.Name == c.Name {
			continue
		}
		// tunnel_port: the listening side binds it. Two listeners on one port
		// cannot both bind; two dialers aimed at the same peer:port would feed
		// the same remote tunnel.
		if c.TunnelPort > 0 && c.TunnelPort == o.TunnelPort {
			switch {
			// A raw-IP carrier has no ports, so nothing binds this and the usual
			// reasoning does not apply. Every raw socket for that protocol on the
			// host receives every packet of it, and the tunnel port is what each
			// frame carries so a tunnel can tell its own traffic from its
			// neighbour's. Two such tunnels sharing one are indistinguishable to
			// each other whichever way round their roles are — each answers the
			// other's peer, and both carry two interleaved ciphertext streams.
			case c.UsesRawIPCarrier() && o.UsesRawIPCarrier():
				add("tunnel_port", fmt.Sprint(c.TunnelPort), o.Name,
					"this carrier has no ports, so the tunnel port is the only thing telling "+
						"the two apart — sharing it makes each tunnel read the other's traffic; "+
						"give them different tunnel ports")
			case !c.IsDialer() && !o.IsDialer():
				add("tunnel_port", fmt.Sprint(c.TunnelPort), o.Name,
					"both tunnels listen on this port — the second will fail to bind")
			case c.IsDialer() && o.IsDialer() && c.Peer != "" && c.Peer == o.Peer:
				add("tunnel_port", fmt.Sprint(c.TunnelPort), o.Name,
					"both dial the same peer on the same port — they would join the same remote tunnel")
			}
		}
		if c.HealthPort > 0 && c.HealthPort == o.HealthPort {
			add("health_port", fmt.Sprint(c.HealthPort), o.Name,
				"both bind 127.0.0.1 on this port — the second stats server will fail")
		}
		if c.UsesL3() && o.UsesL3() {
			if ci, oi := strings.TrimSpace(c.TunIface), strings.TrimSpace(o.TunIface); ci != "" && ci == oi {
				add("tun_iface", ci, o.Name,
					"same TUN device name — the second tunnel would attach to the SAME device and steal its packets")
			}
			if overlaps(c.TunIP, o.TunIP) {
				add("tun_ip", strings.TrimSpace(c.TunIP), o.Name,
					"tunnel subnets overlap — routing between the two tunnels becomes ambiguous")
			}
		}
		// SPF listeners all receive copies of matching raw packets and tell each
		// other apart only by the peer's spoofed source address.
		if c.IsSPF() && o.IsSPF() {
			if cd := strings.TrimSpace(c.SpoofDstIP); cd != "" && cd == strings.TrimSpace(o.SpoofDstIP) {
				add("spoof_dst_ip", cd, o.Name,
					"two SPF tunnels expecting the same peer source would receive each other's packets")
			}
		}
		// Client-facing ports (entry side binds them for mux, DNATs them for L3).
		for _, p := range forwardPorts(c) {
			for _, q := range forwardPorts(o) {
				if p == q {
					add("forward port", fmt.Sprint(p), o.Name,
						"the same client-facing port cannot serve two tunnels")
					break
				}
			}
		}
	}
	return out
}

func forwardPorts(c *Config) []int {
	var ports []int
	for _, spec := range c.Forwards {
		f, err := ParseForward(spec, false)
		if err != nil {
			continue
		}
		for p := f.ListenStart; p <= f.ListenEnd; p++ {
			ports = append(ports, p)
		}
	}
	return ports
}

// overlaps reports whether two CIDRs share any address space.
func overlaps(a, b string) bool {
	_, na, err1 := net.ParseCIDR(strings.TrimSpace(a))
	_, nb, err2 := net.ParseCIDR(strings.TrimSpace(b))
	if err1 != nil || err2 != nil {
		return false
	}
	return na.Contains(nb.IP) || nb.Contains(na.IP)
}
