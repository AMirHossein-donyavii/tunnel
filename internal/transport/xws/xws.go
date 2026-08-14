// Package xws carries the tunnel inside a WebSocket whose payload has no
// fingerprint of its own.
//
// The WebSocket transports already look like web traffic to anything reading
// HTTP, and wss hides the upgrade inside TLS. Neither hides what is *in* the
// WebSocket. The tunnel's own handshake opens with the constant bytes
//
//	45 54 02 03 03
//
// at offset zero of the first message of every connection. Anything that can see
// the WebSocket payload therefore has a five-byte signature to match on, and two
// very ordinary things can see it: a plain ws deployment, where the payload is
// not encrypted at all, and a wss deployment behind a CDN or a corporate proxy
// that terminates TLS and forwards the WebSocket onward.
//
// This layers the stealth handshake inside the WebSocket. What a CDN sees is
// still an ordinary WebSocket connection carrying binary messages; what is in
// those messages is uniform random bytes with no header, no version and no
// constant, because that is what the stealth layer produces. The signature is
// gone, and a peer without the token gets silence rather than a reply.
//
// The order is deliberate. The WebSocket is on the outside because that is the
// part a CDN has to understand and route; the obfuscation is on the inside
// because that is where the thing being hidden lives. Wrapping the other way
// round — a WebSocket inside stealth — would hide the WebSocket too, which
// defeats the reason for having one.
package xws

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/transport"
	"github.com/emergency-tunnel/et/internal/transport/stealth"
)

func init() {
	transport.Register(&xTransport{
		name: "xws", base: "ws",
		summary: "WebSocket whose payload has no fingerprint — for a CDN that terminates TLS",
	})
	transport.Register(&xTransport{
		name: "xwss", base: "wss",
		summary: "WebSocket over TLS, payload obfuscated too — survives a proxy that unwraps TLS",
	})
}

// handshakeTimeout bounds the inner exchange. A peer that opens the WebSocket
// and then says nothing must not hold an accept slot.
const handshakeTimeout = 15 * time.Second

type xTransport struct {
	name    string
	base    string
	summary string
}

func (t *xTransport) Name() string       { return t.name }
func (t *xTransport) Experimental() bool { return false }
func (t *xTransport) Summary() string    { return t.summary }

// tokenFor returns the pre-shared token the inner layer needs. Without one the
// layer would authenticate nobody and answer every prober, which is the whole
// thing it exists to avoid — so it is refused rather than silently weakened.
func tokenFor(cfg *config.Config, name string) (string, error) {
	t := strings.TrimSpace(cfg.Token)
	if t == "" {
		return "", fmt.Errorf("transport %q needs a token: set token = \"...\" to the SAME value on both servers", name)
	}
	if len(t) < 16 {
		return "", fmt.Errorf("token is too short (%d chars): use at least 16 so it cannot be guessed", len(t))
	}
	return t, nil
}

func (t *xTransport) NewDialer(cfg *config.Config, log *logx.Logger) (transport.Dialer, error) {
	tok, err := tokenFor(cfg, t.name)
	if err != nil {
		return nil, err
	}
	base, err := transport.Get(t.base)
	if err != nil {
		return nil, err
	}
	inner, err := base.NewDialer(cfg, log)
	if err != nil {
		return nil, err
	}
	return &dialer{inner: inner, token: tok}, nil
}

func (t *xTransport) NewListener(cfg *config.Config, log *logx.Logger) (transport.Listener, error) {
	tok, err := tokenFor(cfg, t.name)
	if err != nil {
		return nil, err
	}
	base, err := transport.Get(t.base)
	if err != nil {
		return nil, err
	}
	inner, err := base.NewListener(cfg, log)
	if err != nil {
		return nil, err
	}
	l := &listener{
		inner: inner, token: tok, log: log,
		ready: make(chan net.Conn, 8),
		fatal: make(chan error, 1),
		done:  make(chan struct{}),
	}
	go l.pump()
	return l, nil
}

type dialer struct {
	inner transport.Dialer
	token string
}

func (d *dialer) Dial(ctx context.Context) (net.Conn, error) {
	raw, err := d.inner.Dial(ctx)
	if err != nil {
		return nil, err
	}
	c, err := stealth.ClientHandshake(raw, d.token, handshakeTimeout)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return c, nil
}

func (d *dialer) Close() error { return d.inner.Close() }

type listener struct {
	inner transport.Listener
	token string
	log   *logx.Logger

	ready chan net.Conn
	fatal chan error
	done  chan struct{}
	once  sync.Once
}

// pump accepts and handshakes concurrently.
//
// Doing the inner handshake on the accept path would serialise every connection
// behind it, so one peer that opens a WebSocket and then stalls would stop every
// other peer connecting for the length of the timeout. That is a denial of
// service anyone who can reach the port can perform, which is why each
// connection is handshaked on its own goroutine and only finished ones are
// offered.
func (l *listener) pump() {
	for {
		raw, err := l.inner.Accept()
		if err != nil {
			select {
			case l.fatal <- err:
			default:
			}
			return
		}
		go func() {
			c, err := stealth.ServerHandshake(raw, l.token, handshakeTimeout)
			if err != nil {
				// A peer without the token gets silence, not an error message:
				// the stealth layer has already closed without writing anything,
				// so a probe finds a WebSocket that accepts and says nothing.
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
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case err := <-l.fatal:
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *listener) Addr() net.Addr { return l.inner.Addr() }

func (l *listener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.inner.Close()
}
