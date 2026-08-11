package config

import (
	"fmt"
	"strconv"
	"strings"
)

// unmarshal fills known fields of *Config from a flat TOML document.
// It supports: comments (#), key = value, quoted strings, integers, booleans,
// and single-line string arrays. Unknown keys are ignored so configs stay
// forward-compatible.
func unmarshal(data []byte, c *Config) error {
	for n, line := range strings.Split(string(data), "\n") {
		s := strings.TrimSpace(stripComment(line))
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "[") { // no tables in this schema
			continue
		}
		eq := strings.Index(s, "=")
		if eq < 0 {
			return fmt.Errorf("line %d: missing '='", n+1)
		}
		key := strings.TrimSpace(s[:eq])
		val := strings.TrimSpace(s[eq+1:])
		if err := assign(c, key, val); err != nil {
			return fmt.Errorf("line %d (%s): %w", n+1, key, err)
		}
	}
	return nil
}

func assign(c *Config, key, val string) error {
	switch key {
	case "name":
		c.Name = unquote(val)
	case "role":
		c.Role = unquote(val)
	case "transport":
		c.Transport = unquote(val)
	case "mode":
		c.Mode = unquote(val)
	case "peer":
		c.Peer = unquote(val)
	case "tun_mode":
		c.TunMode = unquote(val)
	case "spf_profile":
		c.SpfProfile = unquote(val)
	case "encapsulation":
		c.Encapsulation = unquote(val)
	case "spoof_src_ip":
		c.SpoofSrcIP = unquote(val)
	case "spoof_dst_ip":
		c.SpoofDstIP = unquote(val)
	case "tun_ip":
		c.TunIP = unquote(val)
	case "tun_ip6":
		c.TunIP6 = unquote(val)
	case "peer_tun_ip":
		c.PeerTunIP = unquote(val)
	case "tun_iface":
		c.TunIface = unquote(val)
	case "cipher":
		c.Cipher = unquote(val)
	case "profile":
		c.Profile = unquote(val)
	case "log_level":
		c.LogLevel = unquote(val)
	case "engine":
		c.Engine = unquote(val)
	case "exit_host":
		c.ExitHost = unquote(val)
	case "heartbeat_interval":
		return intField(val, &c.HeartbeatInterval)
	case "heartbeat_timeout":
		return intField(val, &c.HeartbeatTimeout)
	case "batch_size":
		return intField(val, &c.BatchSize)
	case "channel_size":
		return intField(val, &c.ChannelSize)
	case "so_sndbuf":
		return intField(val, &c.SoSndbuf)
	case "so_rcvbuf":
		return intField(val, &c.SoRcvbuf)
	case "tunnel_port":
		return intField(val, &c.TunnelPort)
	case "listen_port": // deprecated alias for tunnel_port (backward compat)
		return intField(val, &c.TunnelPort)
	case "mtu":
		return intField(val, &c.MTU)
	case "workers":
		return intField(val, &c.Workers)
	case "pool":
		return intField(val, &c.Pool)
	case "tun_queues":
		return intField(val, &c.TunQueues)
	case "health_port":
		return intField(val, &c.HealthPort)
	case "proxy_protocol":
		b, err := strconv.ParseBool(strings.TrimSpace(val))
		if err != nil {
			return fmt.Errorf("expected true/false")
		}
		c.ProxyProtocol = b
	case "forwards":
		arr, err := parseStringArray(val)
		if err != nil {
			return err
		}
		c.Forwards = arr
	case "ws_path":
		c.WSPath = unquote(val)
	case "ws_host":
		c.WSHost = unquote(val)
	case "token":
		c.Token = unquote(val)
	case "fec_data":
		return intField(val, &c.FECData)
	case "fec_parity":
		return intField(val, &c.FECParity)
	case "low_latency":
		b, err := strconv.ParseBool(strings.TrimSpace(val))
		if err != nil {
			return fmt.Errorf("expected true/false")
		}
		c.LowLatency = b
	default:
		// A key this build does not know is almost always a typo or an option
		// from a newer version, and either way the setting does nothing. Silently
		// dropping it is how ws_path, low_latency and the rest came to be written
		// by the console and ignored by the core for releases at a time — the
		// tunnel comes up looking correct and simply does not have the behaviour
		// that was asked for. They are collected here and reported rather than
		// discarded; see Config.Unknown.
		c.unknown = append(c.unknown, key)
	}
	return nil
}

func intField(val string, dst *int) error {
	i, err := strconv.Atoi(strings.TrimSpace(val))
	if err != nil {
		return fmt.Errorf("expected integer")
	}
	*dst = i
	return nil
}

func stripComment(line string) string {
	inStr := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inStr = !inStr
		case '#':
			if !inStr {
				return line[:i]
			}
		}
	}
	return line
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if u, err := strconv.Unquote(s); err == nil {
			return u
		}
		return s[1 : len(s)-1]
	}
	return s
}

func parseStringArray(val string) ([]string, error) {
	val = strings.TrimSpace(val)
	if !strings.HasPrefix(val, "[") || !strings.HasSuffix(val, "]") {
		return nil, fmt.Errorf("expected [ ... ] array")
	}
	inner := strings.TrimSpace(val[1 : len(val)-1])
	if inner == "" {
		return nil, nil
	}
	var out []string
	for _, part := range splitTopLevel(inner) {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		out = append(out, unquote(p))
	}
	return out, nil
}

// splitTopLevel splits on commas that are not inside quotes.
func splitTopLevel(s string) []string {
	var out []string
	var buf strings.Builder
	inStr := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch ch {
		case '"':
			inStr = !inStr
			buf.WriteByte(ch)
		case ',':
			if inStr {
				buf.WriteByte(ch)
			} else {
				out = append(out, buf.String())
				buf.Reset()
			}
		default:
			buf.WriteByte(ch)
		}
	}
	if buf.Len() > 0 {
		out = append(out, buf.String())
	}
	return out
}

// Marshal renders the config back to canonical TOML.
func (c *Config) Marshal() string {
	var b strings.Builder
	b.WriteString("# Emergency Tunnel configuration\n")
	b.WriteString("# Managed by the Emergency Tunnel panel. Manual edits are preserved.\n\n")
	kv := func(k, v string) { fmt.Fprintf(&b, "%s = %q\n", k, v) }
	ki := func(k string, v int) { fmt.Fprintf(&b, "%s = %d\n", k, v) }
	kb := func(k string, v bool) { fmt.Fprintf(&b, "%s = %t\n", k, v) }

	kv("name", c.Name)
	kv("role", c.Role)
	kv("engine", c.Engine)
	kv("transport", c.Transport)
	kv("mode", c.Mode)
	if c.Peer != "" {
		kv("peer", c.Peer)
	}
	ki("tunnel_port", c.TunnelPort)
	if c.IsTUN() {
		kv("tun_mode", c.TunMode)
	}
	if c.IsSPF() {
		kv("spf_profile", c.SpfProfile)
		kv("encapsulation", c.Encapsulation)
		kv("spoof_src_ip", c.SpoofSrcIP)
		kv("spoof_dst_ip", c.SpoofDstIP)
	}
	if c.TunIP != "" {
		kv("tun_ip", c.TunIP)
	}
	if c.TunIP6 != "" {
		kv("tun_ip6", c.TunIP6)
	}
	if c.PeerTunIP != "" {
		kv("peer_tun_ip", c.PeerTunIP)
	}
	kv("tun_iface", c.TunIface)
	ki("mtu", c.MTU)
	ki("workers", c.Workers)
	ki("pool", c.Pool)
	kv("cipher", c.Cipher)
	ki("health_port", c.HealthPort)
	kv("profile", c.Profile)
	kv("log_level", c.LogLevel)
	kb("proxy_protocol", c.ProxyProtocol)

	if c.UsesL3() {
		if c.TunQueues > 0 {
			ki("tun_queues", c.TunQueues)
		}
		ki("heartbeat_interval", c.HeartbeatInterval)
		ki("heartbeat_timeout", c.HeartbeatTimeout)
		if c.BatchSize > 0 {
			ki("batch_size", c.BatchSize)
		}
		if c.ChannelSize > 0 {
			ki("channel_size", c.ChannelSize)
		}
		if c.SoSndbuf > 0 {
			ki("so_sndbuf", c.SoSndbuf)
		}
		if c.SoRcvbuf > 0 {
			ki("so_rcvbuf", c.SoRcvbuf)
		}
	}

	if c.Engine == EngineMux && c.ExitHost != "" && c.ExitHost != "127.0.0.1" {
		kv("exit_host", c.ExitHost)
	}

	b.WriteString("forwards = [")
	for i, f := range c.Forwards {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q", f)
	}
	b.WriteString("]\n")
	return b.String()
}
