// Package config defines the Emergency Tunnel configuration schema and a
// dependency-free TOML reader/writer tuned to that schema.
//
// The schema is intentionally flat (scalars + string arrays) so that a small,
// auditable parser can handle it without pulling in a third-party TOML library.
// This keeps the static binary small and the attack surface minimal.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Role identifies which end of the Iran<->Kharej path this host is.
const (
	RoleIran   = "iran"   // entry: users connect here; owns forwarded ports
	RoleKharej = "kharej" // exit: runs the real services (Xray/etc.)
)

// Mode identifies who initiates the tunnel link. Only "reverse" is supported:
// the Foreign (Kharej) server always dials the Iran server.
const (
	ModeReverse = "reverse" // Kharej dials Iran
)

// Performance profiles tune buffer sizes and worker scaling.
const (
	ProfileFast     = "fast"
	ProfileBalance  = "balance"
	ProfileResource = "resource"
)

// Config is the full tunnel definition, one per TOML file.
type Config struct {
	Name       string `toml:"name"`
	Role       string `toml:"role"`
	Transport  string `toml:"transport"`
	Mode       string `toml:"mode"`
	Peer       string `toml:"peer"`        // remote host the dialer connects to
	TunnelPort int    `toml:"tunnel_port"` // server<->server link port (same on both sides)
	TunMode    string `toml:"tun_mode"`    // TUN carrier: tcp | udp | icmp | bip
	// SPF (TUN + IPX-style encapsulation with source-IP spoofing) settings.
	SpfProfile    string `toml:"spf_profile"`   // SPF carrier: icmp | tcp
	Encapsulation string `toml:"encapsulation"` // SPF: "ipx"
	SpoofSrcIP    string `toml:"spoof_src_ip"`  // SPF: spoofed source IP for our packets
	SpoofDstIP    string `toml:"spoof_dst_ip"`  // SPF: peer's spoofed source (inbound filter)
	TunIP         string `toml:"tun_ip"`        // TUN engine: this host's tunnel address (CIDR)
	TunIP6        string `toml:"tun_ip6"`       // TUN engine: optional IPv6 tunnel address (CIDR)
	PeerTunIP     string `toml:"peer_tun_ip"`   // TUN engine: peer's tunnel address (for routing/logs)
	TunIface      string `toml:"tun_iface"`
	MTU           int    `toml:"mtu"`
	Workers       int    `toml:"workers"` // 0 = auto
	Pool          int    `toml:"pool"`
	// TunQueues sets the number of TUN queues / carrier links for the L3 engines
	// (0 = use Pool). It MUST be identical on both servers: the kernel steers
	// flows across all queues, so a queue without a peer link silently blackholes
	// every flow hashed to it. Decoupled from Pool only so the mux session count
	// and the TUN queue count can differ if ever needed.
	TunQueues  int    `toml:"tun_queues"`
	Cipher     string `toml:"cipher"`
	HealthPort int    `toml:"health_port"`
	Profile    string `toml:"profile"`
	LogLevel   string `toml:"log_level"`

	// Engine selects the data plane:
	//   "mux" (default) — TCP Reverse Tunnel: many user streams multiplexed over
	//                     a small pool of encrypted links (lowest latency).
	//   "tun"           — virtual network interface (L3): a TUN device carrying
	//                     all IP traffic (TCP/UDP/ICMP/ICMPv6) over the tunnel.
	Engine string `toml:"engine"`

	// TUN / tuning knobs (ignored by the mux engine).
	HeartbeatInterval int `toml:"heartbeat_interval"` // seconds; 0 = default
	HeartbeatTimeout  int `toml:"heartbeat_timeout"`  // seconds; 0 = default
	BatchSize         int `toml:"batch_size"`         // packets per batch; 0 = auto
	ChannelSize       int `toml:"channel_size"`       // per-queue queue depth; 0 = auto
	SoSndbuf          int `toml:"so_sndbuf"`          // bytes; 0 = OS default
	SoRcvbuf          int `toml:"so_rcvbuf"`          // bytes; 0 = OS default

	// LowLatency switches latency-sensitive protocols (currently the reliable
	// UDP transport) into their latency-first mode: shorter timers, shallower
	// windows and gentler congestion backoff. The Gaming section sets it.
	LowLatency bool `toml:"low_latency"`

	// WSPath / WSHost shape the WebSocket transport's HTTP upgrade. The path
	// must match on both servers; a non-default one also makes the listener
	// answer 404 to anything else, so a probe sees an ordinary web server.
	// WSHost sets the Host header — set it to the CDN hostname when fronting.
	WSPath string `toml:"ws_path"`
	WSHost string `toml:"ws_host"`

	// ExitHost is where the exit (Kharej) dials forwarded services (mux engine).
	// Default 127.0.0.1; set to the address the local service binds if it is not
	// on loopback (mirrors the TUN engine's peer_tun_ip reachability).
	ExitHost string `toml:"exit_host"`

	// ProxyProtocol is the default; individual forwards may override with "@pp".
	ProxyProtocol bool `toml:"proxy_protocol"`

	// Forwards use the syntax:
	//   "2096"        listen 2096 -> remote 2096
	//   "8000=9000"   listen 8000 -> remote 9000
	//   "200-300"     listen 200..300 -> same remote ports
	//   "2096@pp"     enable PROXY protocol v2 for this entry
	Forwards []string `toml:"forwards"`
}

// Defaults returns a Config pre-filled with the recommended defaults.
func Defaults() Config {
	return Config{
		Transport:     "tcp",
		Mode:          ModeReverse,
		TunnelPort:    1234, // server<->server link (same on both sides)
		TunIface:      "emergency-tun",
		MTU:           1380,
		Workers:       0,
		Pool:          4, // MUST match on both servers for TUN/SPF (see TunQueues)
		Cipher:        "chacha20-poly1305",
		HealthPort:    9090, // local stats endpoint (kept off the tunnel port)
		Profile:       ProfileBalance,
		LogLevel:      "info",
		ExitHost:      "127.0.0.1",
		ProxyProtocol: false,

		// TCP Reverse Tunnel (multiplexed) is the primary, recommended engine.
		Engine:            EngineMux,
		TunMode:           TunModeTCP,
		SpfProfile:        SpfProfileICMP,
		Encapsulation:     "ipx",
		HeartbeatInterval: 10,
		HeartbeatTimeout:  25,
	}
}

// Engine identifiers.
const (
	EngineMux    = "mux"    // TCP Reverse Tunnel (multiplexed streams over few links)
	EngineDirect = "direct" // one tunnel connection per user connection
	EngineTUN    = "tun"    // virtual network interface (L3, all IP protocols)
	EngineSPF    = "spf"    // TUN + IPX-style encapsulation with source-IP spoofing
	EngineL3     = "l3"     // deprecated alias for EngineTUN (normalised on load)
)

// IsTUN reports whether the config selects the TUN engine (accepts the "l3" alias).
func (c *Config) IsTUN() bool { return c.Engine == EngineTUN || c.Engine == EngineL3 }

// IsSPF reports whether the config selects the SPF engine.
func (c *Config) IsSPF() bool { return c.Engine == EngineSPF }

// UsesL3 reports whether the engine is built on the L3/TUN data plane.
func (c *Config) UsesL3() bool { return c.IsTUN() || c.IsSPF() }

// TUN carrier modes (how the encrypted link between the two servers is carried).
const (
	TunModeTCP  = "tcp"  // reliable TCP stream (default, production)
	TunModeUDP  = "udp"  // UDP datagrams (low overhead)
	TunModeICMP = "icmp" // inside ICMP echo (IPv4) — beta, needs CAP_NET_RAW
	TunModeBIP  = "bip"  // inside ICMPv6 echo — beta, needs CAP_NET_RAW
)

// SPF carrier profiles.
const (
	SpfProfileICMP = "icmp"
	SpfProfileTCP  = "tcp"
)

// TunModeName returns a human label for a carrier mode.
func TunModeName(m string) string {
	switch m {
	case TunModeUDP:
		return "UDP"
	case TunModeICMP:
		return "ICMP"
	case TunModeBIP:
		return "BIP (ICMPv6)"
	default:
		return "TCP"
	}
}

// Validate checks the config for internal consistency and returns a helpful
// error describing the first problem found.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if c.Role != RoleIran && c.Role != RoleKharej {
		return fmt.Errorf("role must be %q or %q, got %q", RoleIran, RoleKharej, c.Role)
	}
	if c.Mode != ModeReverse {
		return fmt.Errorf("mode must be %q (Kharej dials Iran); direct mode was removed", ModeReverse)
	}
	if c.TunnelPort < 1 || c.TunnelPort > 65535 {
		return fmt.Errorf("tunnel_port out of range: %d", c.TunnelPort)
	}
	if c.Pool < 1 || c.Pool > 1024 {
		return fmt.Errorf("pool out of range (1..1024): %d", c.Pool)
	}
	if c.MTU < 576 || c.MTU > 9000 {
		return fmt.Errorf("mtu out of range (576..9000): %d", c.MTU)
	}
	switch c.Cipher {
	case "chacha20-poly1305", "aes-256-gcm":
	default:
		return fmt.Errorf("cipher must be chacha20-poly1305 or aes-256-gcm, got %q", c.Cipher)
	}
	if c.HealthPort != 0 && c.HealthPort == c.TunnelPort {
		return fmt.Errorf("health_port (%d) must differ from the tunnel_port", c.HealthPort)
	}
	if c.Engine != EngineMux && c.Engine != EngineDirect && !c.IsTUN() && !c.IsSPF() {
		return fmt.Errorf("engine must be %q (multiplexed), %q (per-connection), %q (TUN) or %q (SPF), got %q",
			EngineMux, EngineDirect, EngineTUN, EngineSPF, c.Engine)
	}
	// The dialer side needs to know where to connect.
	if c.dialerSide() && strings.TrimSpace(c.Peer) == "" {
		return fmt.Errorf("peer is required on the dialing side (role=%s mode=%s)", c.Role, c.Mode)
	}

	// Heartbeat: compare EFFECTIVE values (after the runtime defaults of 10s/25s),
	// so setting only the interval (e.g. 30) can't leave the timeout defaulted to
	// 25 ≤ 30 and tear links down before the first heartbeat arrives. Applies to
	// every engine (mux keepalive and L3 heartbeat share these fields).
	ei, et := c.HeartbeatInterval, c.HeartbeatTimeout
	if ei <= 0 {
		ei = 10
	}
	if et <= 0 {
		et = 25
	}
	if et <= ei {
		return fmt.Errorf("heartbeat_timeout (effective %ds) must be greater than heartbeat_interval (effective %ds)", et, ei)
	}

	// Port forwarding (the client-facing VPN/service port) belongs ONLY to the
	// Iran (entry) server, for every engine. The Foreign server just carries the
	// tunnel; it never binds client ports or installs NAT.
	if c.Role != RoleIran && len(c.Forwards) > 0 {
		return fmt.Errorf("forwards are configured on the Iran (entry) server only; remove them from this %s config", c.Role)
	}

	// The TUN/SPF engines are virtual network interfaces: they need a tunnel address.
	if c.IsTUN() {
		return c.validateTUN()
	}
	if c.IsSPF() {
		return c.validateSPF()
	}

	// --- mux engine: VPN/listen port forwarding rules --------------------
	// Only the entry side (Iran) owns forwards.
	if c.Role == RoleIran && len(c.Forwards) == 0 {
		return fmt.Errorf("at least one forward is required on the iran (entry) side")
	}
	// When this host also binds the tunnel link (i.e. it is the listener), a
	// forwarded (listen/VPN) port must not collide with the tunnel_port.
	entryBindsLink := c.Role == RoleIran && !c.dialerSide()
	for _, spec := range c.Forwards {
		f, err := ParseForward(spec, c.ProxyProtocol)
		if err != nil {
			return fmt.Errorf("invalid forward %q: %w", spec, err)
		}
		if entryBindsLink {
			for p := f.ListenStart; p <= f.ListenEnd; p++ {
				if p == c.TunnelPort {
					return fmt.Errorf("listen port %q collides with tunnel_port %d — use a different VPN/listen port", spec, c.TunnelPort)
				}
			}
		}
	}
	return nil
}

// validateTUN validates the TUN-engine addressing (IPv4 required, IPv6 optional)
// and the peer/heartbeat settings.
func (c *Config) validateTUN() error {
	switch c.TunMode {
	case TunModeTCP, TunModeUDP, TunModeICMP, TunModeBIP:
	case "":
		c.TunMode = TunModeTCP
	default:
		return fmt.Errorf("tun_mode must be tcp, udp, icmp or bip, got %q", c.TunMode)
	}
	// bip carries the link inside ICMPv6, so the peer address it dials must be
	// IPv6. Catching an IPv4 literal here turns a permanent reconnect loop —
	// "no suitable address found", once per queue every five seconds — into a
	// message at the moment the config is written. A hostname is left to the
	// runtime, which cannot know its addresses until it resolves them.
	if c.TunMode == TunModeBIP && c.Peer != "" {
		if pip := net.ParseIP(strings.TrimSpace(c.Peer)); pip != nil && pip.To4() != nil {
			return fmt.Errorf("peer %q is IPv4 but tun_mode=bip carries the link inside ICMPv6 — set peer to the other server's IPv6 address, or use tun_mode=icmp for IPv4", c.Peer)
		}
	}
	ip, ipnet, err := net.ParseCIDR(strings.TrimSpace(c.TunIP))
	if err != nil {
		return fmt.Errorf("tun_ip must be an address with prefix, e.g. 10.10.10.1/24 (got %q)", c.TunIP)
	}
	if ip.To4() == nil {
		return fmt.Errorf("tun_ip must be an IPv4 address (use tun_ip6 for IPv6): %q", c.TunIP)
	}
	if c.PeerTunIP != "" {
		pip := net.ParseIP(strings.TrimSpace(c.PeerTunIP))
		if pip == nil {
			return fmt.Errorf("peer_tun_ip is not a valid IP: %q", c.PeerTunIP)
		}
		if !ipnet.Contains(pip) {
			return fmt.Errorf("peer_tun_ip %s is not inside the tunnel subnet %s", c.PeerTunIP, ipnet)
		}
		if pip.Equal(ip) {
			return fmt.Errorf("peer_tun_ip must differ from tun_ip (%s)", ip)
		}
	}
	if c.TunIP6 != "" {
		ip6, _, err := net.ParseCIDR(strings.TrimSpace(c.TunIP6))
		if err != nil || ip6.To4() != nil {
			return fmt.Errorf("tun_ip6 must be an IPv6 address with prefix, e.g. fd00::1/64 (got %q)", c.TunIP6)
		}
	}
	// (Heartbeat interval/timeout ordering is validated centrally in Validate.)
	// Port forwarding is optional for the L3 engines, but when present each spec
	// must parse and needs a peer_tun_ip to DNAT toward across the tunnel.
	if len(c.Forwards) > 0 {
		if strings.TrimSpace(c.PeerTunIP) == "" {
			return fmt.Errorf("port forwarding requires peer_tun_ip (the DNAT target across the tunnel)")
		}
		for _, spec := range c.Forwards {
			if _, err := ParseForward(spec, false); err != nil {
				return fmt.Errorf("invalid forward %q: %w", spec, err)
			}
		}
	}
	return nil
}

// validateSPF validates the SPF engine: a TUN interface plus IPX-style
// encapsulation with source-IP spoofing between the two configured endpoints.
func (c *Config) validateSPF() error {
	// Reuse the TUN addressing checks (tun_ip, peer_tun_ip, tun_ip6, heartbeat).
	if err := c.validateTUN(); err != nil {
		return err
	}
	switch c.SpfProfile {
	case SpfProfileICMP, SpfProfileTCP:
	case "":
		c.SpfProfile = SpfProfileICMP
	default:
		return fmt.Errorf("spf_profile must be icmp or tcp, got %q", c.SpfProfile)
	}
	// Source-IP spoofing is a point-to-point tunnel feature: both spoof
	// addresses are required, must be valid, and must differ.
	src := net.ParseIP(strings.TrimSpace(c.SpoofSrcIP))
	dst := net.ParseIP(strings.TrimSpace(c.SpoofDstIP))
	if src == nil {
		return fmt.Errorf("spoof_src_ip is required and must be a valid IP for the SPF engine")
	}
	if dst == nil {
		return fmt.Errorf("spoof_dst_ip is required and must be a valid IP for the SPF engine")
	}
	if src.Equal(dst) {
		return fmt.Errorf("spoof_src_ip and spoof_dst_ip must differ (they are reversed on the two servers)")
	}
	return nil
}

// dialerSide reports whether THIS host initiates the tunnel link.
// Reverse-only: the Kharej (Foreign) server always dials.
func (c *Config) dialerSide() bool {
	return c.Role == RoleKharej
}

// IsDialer is the exported form of dialerSide.
func (c *Config) IsDialer() bool { return c.dialerSide() }

// IsEntry reports whether this host is the user-facing (Iran) side.
func (c *Config) IsEntry() bool { return c.Role == RoleIran }

// Forward is a parsed port-forwarding rule.
type Forward struct {
	ListenStart int  // first local port
	ListenEnd   int  // last local port (== ListenStart for single/mapping)
	RemoteBase  int  // remote port for ListenStart; offsets follow for ranges
	ProxyProto  bool // emit PROXY protocol v2 to the exit-side service
	LowLatency  bool // open as a high-priority mux stream (gaming/interactive)
	Raw         string
}

// ParseForward parses one forward spec. Flags are "@"-separated suffixes and may
// be combined, e.g. "443@pp@ll". defProxy is the global proxy-protocol default,
// overridable per spec with @pp / @nopp; @ll marks the port low-latency.
func ParseForward(spec string, defProxy bool) (Forward, error) {
	raw := spec
	pp := defProxy
	ll := false
	spec = strings.TrimSpace(spec)
	if i := strings.Index(spec, "@"); i >= 0 {
		flagsPart := spec[i+1:]
		spec = strings.TrimSpace(spec[:i])
		for _, flag := range strings.Split(flagsPart, "@") {
			switch strings.ToLower(strings.TrimSpace(flag)) {
			case "pp", "proxy", "proxyproto":
				pp = true
			case "nopp", "noproxy":
				pp = false
			case "ll", "lowlatency", "gaming":
				ll = true
			default:
				return Forward{}, fmt.Errorf("unknown flag %q (use @pp, @nopp or @ll)", flag)
			}
		}
	}
	f := Forward{ProxyProto: pp, LowLatency: ll, Raw: raw}
	switch {
	case strings.Contains(spec, "="): // mapping local=remote
		parts := strings.SplitN(spec, "=", 2)
		l, err := port(parts[0])
		if err != nil {
			return f, err
		}
		r, err := port(parts[1])
		if err != nil {
			return f, err
		}
		f.ListenStart, f.ListenEnd, f.RemoteBase = l, l, r
	case strings.Contains(spec, "-"): // range
		parts := strings.SplitN(spec, "-", 2)
		lo, err := port(parts[0])
		if err != nil {
			return f, err
		}
		hi, err := port(parts[1])
		if err != nil {
			return f, err
		}
		if hi < lo {
			return f, fmt.Errorf("range end %d < start %d", hi, lo)
		}
		if hi-lo > 4096 {
			return f, fmt.Errorf("range too large (%d ports, max 4096)", hi-lo+1)
		}
		f.ListenStart, f.ListenEnd, f.RemoteBase = lo, hi, lo
	default: // single
		p, err := port(spec)
		if err != nil {
			return f, err
		}
		f.ListenStart, f.ListenEnd, f.RemoteBase = p, p, p
	}
	return f, nil
}

// RemoteFor maps a listening port back to its remote port.
func (f Forward) RemoteFor(listen int) int {
	return f.RemoteBase + (listen - f.ListenStart)
}

func port(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("port %q is not a number", s)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("port %d out of range", p)
	}
	return p, nil
}

// Load reads and validates a TOML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := Defaults()
	if err := unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	if c.Engine == EngineL3 { // normalise the deprecated alias
		c.Engine = EngineTUN
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return &c, nil
}

// LoadRelaxed parses a config WITHOUT validating it. It is used to take stock of
// the tunnels already present on a host (see ScanDir): a peer's config, a config
// for the other role, or one that is currently invalid must still contribute its
// used ports/interfaces/subnets so a new tunnel does not collide with it.
func LoadRelaxed(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := Defaults()
	if err := unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	if c.Engine == EngineL3 { // normalise the deprecated alias
		c.Engine = EngineTUN
	}
	if strings.TrimSpace(c.Name) == "" { // fall back to the file name
		c.Name = strings.TrimSuffix(filepath.Base(path), ".toml")
	}
	return &c, nil
}

// ScanDir returns every tunnel config in dir (relaxed-parsed), sorted by name.
// Unreadable or unparseable files are skipped rather than failing the scan — the
// caller's job is conflict avoidance, not validating someone else's file.
func ScanDir(dir string) []*Config {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []*Config
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		c, err := LoadRelaxed(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Save writes the config as TOML with secure (0600) permissions.
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(c.Marshal()), 0o600)
}
