package transport

import (
	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
)

// experimental is a placeholder transport that is registered (so the panel can
// advertise it and configs can be authored ahead of time) but returns
// ErrNotImplemented when a build without the real implementation tries to use
// it. Each real transport package can later shadow this by registering a
// working Transport under the same name.
type experimental struct {
	name    string
	summary string
}

func (e experimental) Name() string       { return e.name }
func (e experimental) Experimental() bool { return true }
func (e experimental) Summary() string    { return e.summary }

func (e experimental) NewDialer(*config.Config, *logx.Logger) (Dialer, error) {
	return nil, ErrNotImplemented{Transport: e.name}
}

func (e experimental) NewListener(*config.Config, *logx.Logger) (Listener, error) {
	return nil, ErrNotImplemented{Transport: e.name}
}

// registerIfAbsent registers t only if no transport with its name exists yet,
// so a real implementation compiled into the binary always wins.
func registerIfAbsent(t Transport) {
	if _, exists := registry[t.Name()]; !exists {
		registry[t.Name()] = t
	}
}

func init() {
	registerIfAbsent(experimental{"ipx", "Protocol mimicry (ICMP/IPIP/GRE/OSPF) — experimental"})
	registerIfAbsent(experimental{"dns", "DNS over UDP/53 with reliable layer — experimental"})
	registerIfAbsent(experimental{"ssh", "SSH/TCP-22 camouflage transport — experimental"})
	registerIfAbsent(experimental{"hysteria", "QUIC/UDP low-latency transport — experimental"})
}
