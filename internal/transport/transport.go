// Package transport defines the pluggable link layer for Emergency Tunnel.
//
// A transport is responsible only for establishing a RAW (pre-handshake)
// net.Conn between the two hosts — by dialing or by accepting. The common
// crypto handshake, AEAD framing, pooling and forwarding logic live above this
// interface, so every transport (tcp, dns, ssh, hysteria, ipx) automatically
// inherits authentication, encryption and port forwarding.
package transport

import (
	"context"
	"fmt"
	"net"
	"sort"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
)

// Dialer establishes outbound raw links to the peer (used on the dialing side).
type Dialer interface {
	Dial(ctx context.Context) (net.Conn, error)
	Close() error
}

// Listener accepts inbound raw links from the peer (used on the listening side).
type Listener interface {
	Accept() (net.Conn, error)
	Addr() net.Addr
	Close() error
}

// Transport is a named factory for Dialers and Listeners.
type Transport interface {
	// Name is the transport identifier used in config (e.g. "tcp").
	Name() string
	// Experimental reports whether this transport is production-ready.
	Experimental() bool
	// Summary is a one-line human description for the panel.
	Summary() string
	// NewDialer builds a dialer for cfg (dialing side).
	NewDialer(cfg *config.Config, log *logx.Logger) (Dialer, error)
	// NewListener builds a listener for cfg (listening side).
	NewListener(cfg *config.Config, log *logx.Logger) (Listener, error)
}

var registry = map[string]Transport{}

// Register adds a transport to the global registry. Called from init().
func Register(t Transport) {
	if t == nil || t.Name() == "" {
		panic("transport: invalid registration")
	}
	registry[t.Name()] = t
}

// Get returns the transport for name, or an error listing valid names.
func Get(name string) (Transport, error) {
	t, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown transport %q (available: %v)", name, Names())
	}
	return t, nil
}

// Names returns the sorted list of registered transport names.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// All returns every registered transport, production (non-experimental) ones
// first — so the primary TCP transport leads the list — then experimental,
// each group alphabetical.
func All() []Transport {
	out := make([]Transport, 0, len(registry))
	for _, n := range Names() { // production first
		if !registry[n].Experimental() {
			out = append(out, registry[n])
		}
	}
	for _, n := range Names() { // experimental after
		if registry[n].Experimental() {
			out = append(out, registry[n])
		}
	}
	return out
}

// ErrNotImplemented is returned by experimental transports that are registered
// (so the panel can list them) but not yet wired for data.
type ErrNotImplemented struct{ Transport string }

func (e ErrNotImplemented) Error() string {
	return fmt.Sprintf("transport %q is experimental and not yet implemented in this build", e.Transport)
}
