package l3

import (
	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/nettune"
	"github.com/emergency-tunnel/et/internal/transport"
)

// newSPFCarrier builds the carrier for the SPF engine.
//
// SPF is TUN + IPX-style encapsulation. Two profiles:
//   - "icmp": frames ride in ICMP echo with SOURCE-IP SPOOFING via raw sockets
//     (the point-to-point obfuscation feature). Linux + CAP_NET_RAW — see
//     spf_linux.go. BETA.
//   - "tcp":  a reliable TCP stream carrier (IPX framing, no spoofing — stateless
//     TCP spoofing is impractical). Reuses the standard tcp link.
func newSPFCarrier(cfg *config.Config, log *logx.Logger, isDialer bool, cipher string, tune nettune.Options) (linkDialer, linkListener, error) {
	if cfg.SpfProfile == config.SpfProfileTCP {
		tr, err := transport.Get("tcp")
		if err != nil {
			return nil, nil, err
		}
		if isDialer {
			d, err := tr.NewDialer(cfg, log)
			if err != nil {
				return nil, nil, err
			}
			return &tcpLinkDialer{d: d, cipher: cipher, tune: tune}, nil, nil
		}
		l, err := tr.NewListener(cfg, log)
		if err != nil {
			return nil, nil, err
		}
		return nil, &tcpLinkListener{l: l, cipher: cipher, tune: tune}, nil
	}
	// ICMP profile with source spoofing.
	return newSPFRawCarrier(cfg, isDialer, cipher)
}
