package stealth

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/transport"
)

func init() { transport.Register(&stealthTransport{}) }

type stealthTransport struct{}

func (*stealthTransport) Name() string       { return "stealth" }
func (*stealthTransport) Experimental() bool { return false }
func (*stealthTransport) Summary() string {
	return "TCP with no fingerprint — random-looking bytes; a wrong token gets no reply"
}

// tokenFor returns the pre-shared token, or an error naming the setting. A
// tunnel without one would still work, but it would authenticate nobody and
// answer every scanner — which is the whole thing this transport exists to
// avoid, so it is refused rather than silently weakened.
func tokenFor(cfg *config.Config) (string, error) {
	t := strings.TrimSpace(cfg.Token)
	if t == "" {
		return "", fmt.Errorf("transport %q needs a token: set token = \"...\" to the SAME value on both servers", "stealth")
	}
	if len(t) < 16 {
		return "", fmt.Errorf("token is too short (%d chars): use at least 16 so it cannot be guessed", len(t))
	}
	return t, nil
}

func (*stealthTransport) NewDialer(cfg *config.Config, log *logx.Logger) (transport.Dialer, error) {
	tok, err := tokenFor(cfg)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Peer) == "" {
		return nil, fmt.Errorf("transport %q: peer is required on the dialing side", "stealth")
	}
	return &dialer{
		addr:  net.JoinHostPort(cfg.Peer, fmt.Sprintf("%d", cfg.TunnelPort)),
		token: tok,
		log:   log,
	}, nil
}

func (*stealthTransport) NewListener(cfg *config.Config, log *logx.Logger) (transport.Listener, error) {
	tok, err := tokenFor(cfg)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.TunnelPort))
	if err != nil {
		return nil, err
	}
	log.Info("stealth transport listening on :%d", cfg.TunnelPort)
	return &listener{ln: ln, token: tok, log: log,
		ready: make(chan net.Conn, 8),
		fatal: make(chan error, 1),
		done:  make(chan struct{}),
	}, nil
}

type dialer struct {
	addr  string
	token string
	log   *logx.Logger
}

func (d *dialer) Dial(ctx context.Context) (net.Conn, error) {
	var nd net.Dialer
	raw, err := nd.DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, err
	}
	c, err := ClientHandshake(raw, d.token, 0)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return c, nil
}

func (d *dialer) Close() error { return nil }

type listener struct {
	ln    net.Listener
	token string
	log   *logx.Logger

	once  sync.Once
	ready chan net.Conn
	fatal chan error
	done  chan struct{}
	dOnce sync.Once
}

// Accept returns only peers that proved they hold the token.
//
// The handshake never runs on the accept path. A connection that opens the port
// and then says nothing would otherwise be charged to every real peer queued
// behind it — the full handshake deadline, serially — and on a public port that
// is what a scanner does by accident. Each candidate is handshaked in its own
// goroutine and only authenticated connections are returned, with a ceiling on
// how many can be in flight so a flood is shed rather than queued.
func (l *listener) Accept() (net.Conn, error) {
	l.once.Do(l.start)
	select {
	case c := <-l.ready:
		return c, nil
	case err := <-l.fatal:
		return nil, err
	}
}

// maxPendingHandshakes bounds the goroutines a flood of connections can create.
// Far above any legitimate need — a tunnel opens a handful of links — so
// reaching it means something other than a peer is connecting.
const maxPendingHandshakes = 64

func (l *listener) start() {
	go func() {
		sem := make(chan struct{}, maxPendingHandshakes)
		for {
			raw, err := l.ln.Accept()
			if err != nil {
				select {
				case l.fatal <- err:
				default:
				}
				return
			}
			select {
			case sem <- struct{}{}:
			default:
				_ = raw.Close() // shed rather than queue
				continue
			}
			go func() {
				defer func() { <-sem }()
				c, err := ServerHandshake(raw, l.token, 0)
				if err != nil {
					// Closing without writing is the point: a peer that cannot
					// prove it holds the token learns nothing about this port.
					_ = raw.Close()
					return
				}
				select {
				case l.ready <- c:
				case <-l.done:
					_ = c.Close()
				}
			}()
		}
	}()
}

func (l *listener) Addr() net.Addr { return l.ln.Addr() }

func (l *listener) Close() error {
	l.dOnce.Do(func() { close(l.done) })
	return l.ln.Close()
}
