//go:build !linux

package firewall

import (
	"fmt"

	"github.com/emergency-tunnel/et/internal/config"
)

// Logger mirrors the Linux definition so callers compile on every platform.
type Logger interface {
	Info(string, ...any)
	Warn(string, ...any)
}

// Apply is unsupported off Linux: port forwarding relies on iptables/netfilter.
// It errors only when forwards are actually configured, so a plain TUN/SPF
// tunnel still builds and runs on non-Linux hosts.
func Apply(cfg *config.Config, iface string, log Logger) error {
	if !Enabled(cfg) {
		return nil
	}
	return fmt.Errorf("port forwarding requires Linux (iptables/netfilter)")
}

// Remove is a no-op off Linux.
func Remove(cfg *config.Config, log Logger) {}
