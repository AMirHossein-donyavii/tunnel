//go:build !linux

package l3

import (
	"errors"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
)

// newICMPCarrier is unsupported off Linux (raw ICMP sockets are a Linux feature
// here). The TUN engine runs on Linux servers; this keeps other OSes building.
func newICMPCarrier(mode string, cfg *config.Config, isDialer bool, cipher string, log *logx.Logger) (linkDialer, linkListener, error) {
	return nil, nil, errors.New("ICMP/BIP TUN modes require Linux (raw sockets, CAP_NET_RAW)")
}
