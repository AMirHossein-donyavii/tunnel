//go:build !linux

package l3

import (
	"errors"

	"github.com/emergency-tunnel/et/internal/config"
)

// newSPFRawCarrier (ICMP + source spoofing) is unsupported off Linux.
func newSPFRawCarrier(cfg *config.Config, isDialer bool, cipher string) (linkDialer, linkListener, error) {
	return nil, nil, errors.New("SPF icmp profile requires Linux (raw sockets, CAP_NET_RAW)")
}
