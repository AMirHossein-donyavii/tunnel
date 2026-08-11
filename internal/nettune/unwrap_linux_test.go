//go:build linux

package nettune

import (
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A wrapper conn, as every obfuscated transport returns: WebSocket framing, a
// TLS record layer, the stealth record layer. Each embeds the connection it
// wraps, so the net.Conn methods are promoted and the wrapper is indisting-
// uishable from a socket at the type level — which is exactly how it went
// untuned for so long without anything failing.
type wrapper struct {
	net.Conn
}

func (w wrapper) NetConn() net.Conn { return w.Conn }

// An opaque wrapper: no way down to a socket. Apply must decline, not panic.
type opaque struct{ net.Conn }

func tcpPair(t *testing.T) (*net.TCPConn, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		done <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer := <-done
	return c.(*net.TCPConn), func() {
		c.Close()
		if peer != nil {
			peer.Close()
		}
		ln.Close()
	}
}

func nodelay(t *testing.T, tc *net.TCPConn) int {
	t.Helper()
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var serr error
	if err := raw.Control(func(fd uintptr) {
		v, serr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NODELAY)
	}); err != nil {
		t.Fatal(err)
	}
	if serr != nil {
		t.Fatal(serr)
	}
	return v
}

// The settings must actually land on the socket underneath the wrapping. This
// reads the option back rather than trusting that Apply was called: the bug
// being guarded against was Apply running happily and doing nothing.
func TestApplyReachesTheSocketThroughWrappers(t *testing.T) {
	cases := []struct {
		name string
		wrap func(net.Conn) net.Conn
	}{
		{"bare", func(c net.Conn) net.Conn { return c }},
		{"one-layer", func(c net.Conn) net.Conn { return wrapper{c} }},
		{"two-layers", func(c net.Conn) net.Conn { return wrapper{wrapper{c}} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sock, cleanup := tcpPair(t)
			defer cleanup()

			// Start from the un-tuned default so a pass means Apply did it.
			if err := sock.SetNoDelay(false); err != nil {
				t.Fatal(err)
			}
			if got := nodelay(t, sock); got != 0 {
				t.Fatalf("could not clear TCP_NODELAY first (got %d)", got)
			}

			Apply(tc.wrap(sock), LinkOptions("balance", 0, 0))

			if got := nodelay(t, sock); got != 1 {
				t.Fatalf("TCP_NODELAY is %d after Apply — the tuning never reached the socket, "+
					"so this transport runs with Nagle's algorithm on", got)
			}
		})
	}
}

// A conn with no socket under it must be declined quietly.
func TestApplyDeclinesWhatItCannotReach(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	Apply(c1, LinkOptions("balance", 0, 0))         // no panic
	Apply(opaque{c1}, LinkOptions("balance", 0, 0)) // no NetConn to follow
	Apply(nil, LinkOptions("balance", 0, 0))
}

// A conn that wraps itself must not spin forever.
type selfWrap struct{ net.Conn }

func (s selfWrap) NetConn() net.Conn { return s }

func TestUnwrapTerminatesOnACycle(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		if got := baseTCPConn(selfWrap{}); got != nil {
			t.Errorf("found a TCP conn in a cycle: %v", got)
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("baseTCPConn did not terminate on a self-wrapping conn")
	}
}
