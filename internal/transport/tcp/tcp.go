// Package tcp implements the production TCP transport: raw TCP links with
// tuned sockets (TCP_NODELAY, keepalive), used for both reverse and direct
// modes. Pooling, handshake and forwarding are handled by the layers above.
package tcp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/transport"
)

func init() { transport.Register(Transport{}) }

// Transport is the TCP transport factory.
type Transport struct{}

func (Transport) Name() string       { return "tcp" }
func (Transport) Experimental() bool { return false }
func (Transport) Summary() string {
	return "Raw TCP · pooled · reverse+direct · high throughput (recommended)"
}

func (Transport) NewDialer(cfg *config.Config, log *logx.Logger) (transport.Dialer, error) {
	addr := net.JoinHostPort(cfg.Peer, fmt.Sprintf("%d", cfg.TunnelPort))
	return &dialer{addr: addr, log: log}, nil
}

func (Transport) NewListener(cfg *config.Config, log *logx.Logger) (transport.Listener, error) {
	addr := fmt.Sprintf(":%d", cfg.TunnelPort)
	lc := net.ListenConfig{KeepAlive: 30 * time.Second}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp listen %s: %w", addr, err)
	}
	log.Info("tcp transport listening on %s", addr)
	return &listener{ln: ln}, nil
}

type dialer struct {
	addr string
	log  *logx.Logger
}

func (d *dialer) Dial(ctx context.Context) (net.Conn, error) {
	nd := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	c, err := nd.DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, err
	}
	tune(c)
	return c, nil
}

func (d *dialer) Close() error { return nil }

type listener struct{ ln net.Listener }

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	tune(c)
	return c, nil
}

func (l *listener) Addr() net.Addr { return l.ln.Addr() }
func (l *listener) Close() error   { return l.ln.Close() }

// tune sets low-latency socket options appropriate for tunnel links.
func tune(c net.Conn) {
	if t, ok := c.(*net.TCPConn); ok {
		_ = t.SetNoDelay(true)
		_ = t.SetKeepAlive(true)
		_ = t.SetKeepAlivePeriod(30 * time.Second)
	}
}
