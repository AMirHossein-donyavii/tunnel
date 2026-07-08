//go:build linux

package nettune

import (
	"net"

	"golang.org/x/sys/unix"
)

// TuneConn applies low-latency, high-throughput socket options to an
// established TCP connection. All settings are best-effort; failures are
// ignored so a restrictive kernel never breaks the tunnel.
func TuneConn(c net.Conn, sndbuf, rcvbuf int) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	raw, err := tc.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		ifd := int(fd)
		if sndbuf > 0 {
			_ = unix.SetsockoptInt(ifd, unix.SOL_SOCKET, unix.SO_SNDBUF, sndbuf)
		}
		if rcvbuf > 0 {
			_ = unix.SetsockoptInt(ifd, unix.SOL_SOCKET, unix.SO_RCVBUF, rcvbuf)
		}
		// Prefer BBR when the kernel offers it; silently ignored otherwise.
		_ = unix.SetsockoptString(ifd, unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr")
	})
}
