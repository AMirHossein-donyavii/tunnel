//go:build linux

package nettune

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// Apply sets low-latency, high-throughput socket options on an established TCP
// connection. All settings are best-effort; failures are ignored so a
// restrictive kernel never breaks the tunnel.
func Apply(c net.Conn, o Options) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	if o.Keepalive > 0 {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(o.Keepalive)
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return
	}
	ka := int(o.Keepalive / time.Second)
	ut := int((o.UserTimeout + time.Millisecond - 1) / time.Millisecond)
	_ = raw.Control(func(fd uintptr) {
		ifd := int(fd)
		if o.SndBuf > 0 {
			_ = unix.SetsockoptInt(ifd, unix.SOL_SOCKET, unix.SO_SNDBUF, o.SndBuf)
		}
		if o.RcvBuf > 0 {
			_ = unix.SetsockoptInt(ifd, unix.SOL_SOCKET, unix.SO_RCVBUF, o.RcvBuf)
		}
		// Note: TCP_QUICKACK is intentionally NOT set — it is a one-shot flag on
		// Linux that reverts to delayed-ACK after the next segment, so setting it
		// once at connect is a no-op. TCP_NODELAY (above) is the effective
		// latency knob and applies for the connection's lifetime.
		if o.UserTimeout > 0 {
			// TCP_USER_TIMEOUT: fail fast on unacked data (stalled peers).
			_ = unix.SetsockoptInt(ifd, unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, ut)
		}
		if ka > 0 {
			_ = unix.SetsockoptInt(ifd, unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, ka)
			_ = unix.SetsockoptInt(ifd, unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, ka)
			_ = unix.SetsockoptInt(ifd, unix.IPPROTO_TCP, unix.TCP_KEEPCNT, 3)
		}
		if o.NotSentLowat > 0 {
			// Keep the queue in our scheduler instead of the kernel's send buffer,
			// so priority and AQM still govern it. See nettune.notSentLowat.
			_ = unix.SetsockoptInt(ifd, unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, o.NotSentLowat)
		}
		if o.BBR {
			// Prefer BBR when the kernel offers it; silently ignored otherwise.
			_ = unix.SetsockoptString(ifd, unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr")
		}
	})
}

// TuneConn is the legacy buffer-only entry point (used by the L3 engine).
func TuneConn(c net.Conn, sndbuf, rcvbuf int) {
	o := Options{SndBuf: sndbuf, RcvBuf: rcvbuf, BBR: true, Keepalive: 20 * time.Second, UserTimeout: 12 * time.Second}
	if sndbuf == 0 {
		o.NotSentLowat = notSentLowat
	}
	Apply(c, o)
}
