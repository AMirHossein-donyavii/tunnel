package nettune

import "net"

// baseTCPConn digs the *net.TCPConn out from under however many layers a
// transport has wrapped around it.
//
// Apply used to type-assert straight to *net.TCPConn and give up when that
// failed. Only the plain TCP transport hands back a bare *net.TCPConn: ws wraps
// it in a WebSocket framer, wss in a TLS conn inside that framer, stealth in
// its own record layer. Every one of those silently received no tuning at all —
// which is worse than it sounds, because the most important setting is
// TCP_NODELAY. Without it Nagle's algorithm holds a small write back until the
// previous segment is acknowledged, so on exactly the obfuscated protocols
// people choose when the path is hostile, an interactive packet could wait a
// round-trip before it was even sent. Those protocols also lost BBR, the
// bufferbloat guard (TCP_NOTSENT_LOWAT), and the keepalive/user-timeout that
// makes a dead link fail fast rather than hang.
//
// Both crypto/tls.Conn and utls.Conn expose NetConn(); our own wrappers expose
// the same method, so one loop covers all of them. The depth limit is there so
// a conn that wraps itself cannot spin.
func baseTCPConn(c net.Conn) *net.TCPConn {
	for i := 0; c != nil && i < 8; i++ {
		if tc, ok := c.(*net.TCPConn); ok {
			return tc
		}
		u, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			return nil
		}
		c = u.NetConn()
	}
	return nil
}
