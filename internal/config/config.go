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
	"strconv"
	"strings"
)

// Role identifies which end of the Iran<->Kharej path this host is.
const (
	RoleIran   = "iran"   // entry: users connect here; owns forwarded ports
	RoleKharej = "kharej" // exit: runs the real services (Xray/etc.)
)

// Mode identifies who initiates the tunnel link.
const (
	ModeReverse = "reverse" // Kharej dials Iran (recommended)
	ModeDirect  = "direct"  // Iran dials Kharej
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
	TunIP      string `toml:"tun_ip"`      // TUN engine: this host's tunnel address (CIDR)
	TunIP6     string `toml:"tun_ip6"`     // TUN engine: optional IPv6 tunnel address (CIDR)
	PeerTunIP  string `toml:"peer_tun_ip"` // TUN engine: peer's tunnel address (for routing/logs)
	TunIface   string `toml:"tun_iface"`
	MTU        int    `toml:"mtu"`
	Workers    int    `toml:"workers"` // 0 = auto
	Pool       int    `toml:"pool"`
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
		Pool:          8,
		Cipher:        "chacha20-poly1305",
		HealthPort:    9090, // local stats endpoint (kept off the tunnel port)
		Profile:       ProfileBalance,
		LogLevel:      "info",
		ProxyProtocol: false,

		// TCP Reverse Tunnel (multiplexed) is the primary, recommended engine.
		Engine:            EngineMux,
		HeartbeatInterval: 10,
		HeartbeatTimeout:  25,
	}
}

// Engine identifiers.
const (
	EngineMux = "mux" // TCP Reverse Tunnel (multiplexed streams over few links)
	EngineTUN = "tun" // virtual network interface (L3, all IP protocols)
	EngineL3  = "l3"  // deprecated alias for EngineTUN (normalised on load)
)

// IsTUN reports whether the config selects the TUN engine (accepts the "l3" alias).
func (c *Config) IsTUN() bool { return c.Engine == EngineTUN || c.Engine == EngineL3 }

// Validate checks the config for internal consistency and returns a helpful
// error describing the first problem found.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if c.Role != RoleIran && c.Role != RoleKharej {
		return fmt.Errorf("role must be %q or %q, got %q", RoleIran, RoleKharej, c.Role)
	}
	if c.Mode != ModeReverse && c.Mode != ModeDirect {
		return fmt.Errorf("mode must be %q or %q, got %q", ModeReverse, ModeDirect, c.Mode)
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
	if c.Engine != EngineMux && !c.IsTUN() {
		return fmt.Errorf("engine must be %q (TCP Reverse) or %q (TUN), got %q", EngineMux, EngineTUN, c.Engine)
	}
	// The dialer side needs to know where to connect.
	if c.dialerSide() && strings.TrimSpace(c.Peer) == "" {
		return fmt.Errorf("peer is required on the dialing side (role=%s mode=%s)", c.Role, c.Mode)
	}

	// The TUN engine is a virtual network interface: it needs a tunnel address.
	if c.IsTUN() {
		return c.validateTUN()
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
	if c.HeartbeatTimeout > 0 && c.HeartbeatInterval > 0 && c.HeartbeatTimeout <= c.HeartbeatInterval {
		return fmt.Errorf("heartbeat_timeout (%d) must be greater than heartbeat_interval (%d)", c.HeartbeatTimeout, c.HeartbeatInterval)
	}
	return nil
}

// dialerSide reports whether THIS host initiates the tunnel link.
// reverse => Kharej dials; direct => Iran dials.
func (c *Config) dialerSide() bool {
	if c.Mode == ModeReverse {
		return c.Role == RoleKharej
	}
	return c.Role == RoleIran
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
	Raw         string
}

// ParseForward parses one forward spec. defProxy is the global default applied
// unless the spec carries an explicit "@pp" suffix.
func ParseForward(spec string, defProxy bool) (Forward, error) {
	raw := spec
	pp := defProxy
	spec = strings.TrimSpace(spec)
	if i := strings.Index(spec, "@"); i >= 0 {
		flag := strings.ToLower(strings.TrimSpace(spec[i+1:]))
		spec = strings.TrimSpace(spec[:i])
		switch flag {
		case "pp", "proxy", "proxyproto":
			pp = true
		case "nopp", "noproxy":
			pp = false
		default:
			return Forward{}, fmt.Errorf("unknown flag %q (use @pp or @nopp)", flag)
		}
	}
	f := Forward{ProxyProto: pp, Raw: raw}
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

// Save writes the config as TOML with secure (0600) permissions.
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(c.Marshal()), 0o600)
}
