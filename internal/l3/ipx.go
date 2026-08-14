package l3

import "encoding/binary"

// IPX — the raw-IP carrier family.
//
// The TUN engine already carried its links inside TCP, UDP and ICMP. IPX adds
// the two remaining IP-level protocols that a router forwards without looking
// inside: IP-in-IP (protocol 4) and GRE (protocol 47). Both exist because a path
// that filters TCP and UDP, and polices ICMP, frequently leaves these alone —
// they are what site-to-site tunnels between routers are built from, so dropping
// them breaks ordinary infrastructure and networks are reluctant to do it.
//
// Neither has ports. A raw socket for a protocol number receives every packet of
// that protocol the host receives, exactly like the ICMP carrier, so the same
// two problems appear and take the same answer: a frame says which direction it
// is going and which tunnel it belongs to, and the tunnel port — meaningless to
// these protocols, which is what makes it free to use — separates two tunnels on
// one host.
//
// One difference from ICMP. An echo message has an id field, which the ICMP
// carrier uses to tell the links of a pool apart. IP-in-IP and GRE have no such
// field, so the link id is carried explicitly:
//
//	frame = [direction: 1][tunnel port: 2][link id: 2][sealed frame …]
//
// GRE puts its own four-byte header in front of that. A GRE packet begins with
// flags and a version (all zero for the base protocol) and the protocol type of
// what it carries; emitting a well-formed one means anything on the path that
// understands GRE sees a plain GRE tunnel carrying IPv4, which is the point.
// IP-in-IP has no header at all — the payload of a real one is an opaque inner
// packet that routers do not inspect — so nothing is prepended.

// Direction bytes. These are the same two values the ICMP carrier uses, for the
// same reason: a raw socket receives packets this process sent as well as ones
// it should read, and the direction is what separates them.
const (
	dirToListener = tagToListener
	dirToDialer   = tagToDialer
)

const (
	// ipxHdr is the framing this carrier adds: direction, tunnel, link.
	ipxHdr = 5

	// greHdr is the GRE base header: two bytes of flags/version, then the
	// protocol type of the payload.
	greHdr = 4
	// greProtoIPv4 is what a GRE tunnel carrying IPv4 announces (ETH_P_IP).
	greProtoIPv4 = 0x0800
)

// ipxProfile describes one raw-IP protocol this carrier can ride in.
type ipxProfile struct {
	mode    string // config name: "ipip" / "gre"
	network string // raw-socket network, e.g. "ip4:4"
	label   string // for logs
	prefix  int    // bytes of protocol header before our own framing
}

var (
	ipxIPIP = ipxProfile{mode: "ipip", network: "ip4:4", label: "IP-in-IP", prefix: 0}
	ipxGRE  = ipxProfile{mode: "gre", network: "ip4:47", label: "GRE", prefix: greHdr}
)

func ipxProfileFor(mode string) (ipxProfile, bool) {
	switch mode {
	case ipxIPIP.mode:
		return ipxIPIP, true
	case ipxGRE.mode:
		return ipxGRE, true
	}
	return ipxProfile{}, false
}

// appendIPX writes a complete carrier payload: the protocol's own header, this
// carrier's framing, then the sealed frame. The caller reuses dst across
// packets, so nothing here allocates in the steady state.
func appendIPX(dst []byte, p ipxProfile, dir byte, tunnel, link int, payload []byte) []byte {
	if p.prefix == greHdr {
		dst = append(dst, 0, 0, byte(greProtoIPv4>>8), byte(greProtoIPv4&0xff))
	}
	dst = append(dst, dir, byte(tunnel>>8), byte(tunnel), byte(link>>8), byte(link))
	return append(dst, payload...)
}

// parseIPX accepts a packet only when it is travelling the wanted direction and
// belongs to this tunnel, returning the sealed frame and the link it is for.
//
// Three things fail here rather than reaching the AEAD: traffic going the other
// way (this carrier's own output, since a raw socket sees packets it sent on
// loopback and every host on a shared segment), another tunnel's traffic, and
// somebody else's genuine IP-in-IP or GRE — of which there may be plenty, since
// these protocols carry real infrastructure.
func parseIPX(p ipxProfile, raw []byte, wantDir byte, tunnel int) (payload []byte, link int, ok bool) {
	if len(raw) < p.prefix+ipxHdr {
		return nil, 0, false
	}
	if p.prefix == greHdr {
		// Only the base protocol: no checksum, key or sequence extensions, and
		// version 0. Anything else is not ours.
		if binary.BigEndian.Uint16(raw[0:2]) != 0 ||
			binary.BigEndian.Uint16(raw[2:4]) != greProtoIPv4 {
			return nil, 0, false
		}
	}
	b := raw[p.prefix:]
	if b[0] != wantDir {
		return nil, 0, false
	}
	if int(b[1])<<8|int(b[2]) != tunnel&0xffff {
		return nil, 0, false
	}
	return b[ipxHdr:], int(b[3])<<8 | int(b[4]), true
}
