package l3

import "golang.org/x/net/ipv4"

// The ICMP echo wire format, in one place.
//
// Two carriers put frames inside echo messages: the ICMP/BIP carrier and the
// SPF icmp profile. Both used to build and parse those messages through
// golang.org/x/net/icmp, which allocates a message and a body for every packet
// in both directions — tens of thousands of allocations a second at line rate,
// on servers that are usually one core. The header is eight fixed bytes, so it
// is written into and read out of a caller-owned buffer instead.
//
// Hand-rolling a wire format is only safe if there is exactly one copy of it,
// which is why this file is shared rather than duplicated per carrier, and why
// the framing test asserts these bytes against the library they replaced.

// Direction tags. The first payload byte says which way a datagram is
// travelling, so a packet that comes back to its own sender — a kernel echo
// reply mirroring our own request — is recognisable and dropped.
//
// A listener's kernel answers echo requests by itself, and its reply repeats our
// payload verbatim with the same ICMP id: by address and id alone it is
// indistinguishable from a real reply from the peer. Both ICMP carriers here —
// the TUN icmp/bip modes and the SPF icmp profile — are built on echo messages
// and both are fooled by it. The alternative, switching off echo replies
// host-wide, costs the server the ability to answer ping on any interface,
// including its own tunnel address.
const (
	tagToListener = 0xE1 // dialer -> listener, rides in Echo Requests
	tagToDialer   = 0xE2 // listener -> dialer, rides in Echo Replies
)

// stripTag accepts a payload only when it carries the expected direction tag,
// and returns it with the tag removed. Traffic travelling the other way — our
// own request mirrored back by a kernel echo reply, or a stray ping from a
// stranger — fails here instead of reaching the AEAD as a peer frame.
func stripTag(data []byte, want byte) ([]byte, bool) {
	if len(data) < 1 || data[0] != want {
		return nil, false
	}
	return data[1:], true
}

const (
	icmpEchoHdr = 8 // type, code, checksum, id, seq

	icmpTypeEchoV4      = byte(ipv4.ICMPTypeEcho)      // 8
	icmpTypeEchoReplyV4 = byte(ipv4.ICMPTypeEchoReply) // 0
	icmpTypeEchoV6      = 128
	icmpTypeEchoReplyV6 = 129
)

func echoType(v6, reply bool) byte {
	switch {
	case v6 && reply:
		return icmpTypeEchoReplyV6
	case v6:
		return icmpTypeEchoV6
	case reply:
		return icmpTypeEchoReplyV4
	default:
		return icmpTypeEchoV4
	}
}

// appendEchoHeader appends the eight-byte echo header to dst, leaving the
// checksum zero. Append the payload after it, then call finishICMP over the
// whole message.
func appendEchoHeader(dst []byte, v6, reply bool, id, seq int) []byte {
	return append(dst,
		echoType(v6, reply), 0,
		0, 0, // checksum, filled by finishICMP
		byte(id>>8), byte(id),
		byte(seq>>8), byte(seq),
	)
}

// finishICMP writes the checksum over a complete message.
//
// ICMPv6 checksums cover an IPv6 pseudo-header that a raw socket does not let
// us see; the kernel computes and inserts it, and a non-zero value there would
// be wrong. So v6 is deliberately left alone.
func finishICMP(msg []byte, v6 bool) {
	if v6 || len(msg) < icmpEchoHdr {
		return
	}
	msg[2], msg[3] = 0, 0
	ck := icmpChecksum(msg)
	msg[2], msg[3] = byte(ck>>8), byte(ck)
}

// parseEchoMsg returns the payload after the echo header, and the message's id,
// when raw is an echo of the wanted protocol and direction.
//
// The checksum is not verified: the kernel has already dropped anything that
// failed it, and the AEAD rejects anything the kernel let through — so checking
// it here would cost a pass over every packet and reject nothing.
func parseEchoMsg(raw []byte, v6, wantReply bool) (payload []byte, id int, ok bool) {
	if len(raw) < icmpEchoHdr || raw[0] != echoType(v6, wantReply) {
		return nil, 0, false
	}
	return raw[icmpEchoHdr:], int(raw[4])<<8 | int(raw[5]), true
}

// icmpChecksum is the standard one's-complement sum.
//
// Unlike UDP, whose checksum the kernel (often the NIC) computes, a raw ICMP
// socket leaves this to us, so it runs over every byte of every packet sent —
// the one per-packet cost these carriers pay and the UDP carrier does not. It
// folds four bytes per iteration to keep that cost as low as the arithmetic
// allows; the deferred carries cannot overflow uint64 within one datagram.
func icmpChecksum(b []byte) uint16 {
	var sum uint64
	for len(b) >= 4 {
		sum += uint64(b[0])<<8 | uint64(b[1])
		sum += uint64(b[2])<<8 | uint64(b[3])
		b = b[4:]
	}
	for len(b) >= 2 {
		sum += uint64(b[0])<<8 | uint64(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint64(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
