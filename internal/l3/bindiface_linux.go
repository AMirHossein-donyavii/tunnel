//go:build linux

package l3

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/net/icmp"
)

// bindToDevice ties a socket to one network interface.
//
// A raw socket for an IP protocol has no port, so it receives that protocol from
// every interface the host has. On a server with more than one — a provider's
// public NIC plus a private one, or a box that also terminates a real GRE or
// IP-in-IP tunnel — most of what arrives is not ours, and every packet of it
// costs a wakeup and a parse before the framing rejects it. Binding to the
// device the peer is reachable through removes that traffic in the kernel.
//
// It is also the only way to pin the carrier to a specific link when the routing
// table would otherwise choose another.
//
// Needs CAP_NET_RAW, which these carriers already require.
func bindToDevice(pc net.PacketConn, iface string) error {
	if iface == "" {
		return nil
	}
	if _, err := net.InterfaceByName(iface); err != nil {
		return fmt.Errorf("interface %q: %w", iface, err)
	}
	raw, err := rawConnOf(pc)
	if err != nil {
		return err
	}
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		opErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
	}); err != nil {
		return err
	}
	if opErr != nil {
		return fmt.Errorf("bind to %q: %w", iface, opErr)
	}
	return nil
}

// rawConnOf reaches the file descriptor behind either socket type these carriers
// use: a plain raw PacketConn, or the ICMP wrapper around one.
func rawConnOf(pc net.PacketConn) (syscall.RawConn, error) {
	type controller interface {
		SyscallConn() (syscall.RawConn, error)
	}
	if c, ok := pc.(controller); ok {
		return c.SyscallConn()
	}
	if p, ok := pc.(*icmp.PacketConn); ok {
		if p6 := p.IPv6PacketConn(); p6 != nil {
			if c, ok := p6.PacketConn.(controller); ok {
				return c.SyscallConn()
			}
		}
		if p4 := p.IPv4PacketConn(); p4 != nil {
			if c, ok := p4.PacketConn.(controller); ok {
				return c.SyscallConn()
			}
		}
	}
	return nil, fmt.Errorf("socket does not expose a file descriptor")
}
