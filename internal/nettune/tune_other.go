//go:build !linux

package nettune

import "net"

// TuneConn on non-Linux only sets TCP_NODELAY (the buffer/BBR options are
// Linux-specific). The L3 engine runs on Linux; this keeps other OSes building.
func TuneConn(c net.Conn, sndbuf, rcvbuf int) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
}
