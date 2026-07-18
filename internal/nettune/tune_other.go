//go:build !linux

package nettune

import "net"

// Apply on non-Linux only sets TCP_NODELAY and keepalive (the buffer/
// USER_TIMEOUT/BBR options are Linux-specific). Production runs on Linux; this
// keeps other OSes building and lightly tuned.
func Apply(c net.Conn, o Options) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		if o.Keepalive > 0 {
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(o.Keepalive)
		}
	}
}

// TuneConn is the legacy buffer-only entry point (used by the L3 engine).
func TuneConn(c net.Conn, sndbuf, rcvbuf int) {
	Apply(c, Options{SndBuf: sndbuf, RcvBuf: rcvbuf})
}
