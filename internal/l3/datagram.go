package l3

import (
	"encoding/binary"
)

// Frame payload format (one frame = one AEAD frame on a stream carrier, one
// datagram on a packet carrier):
//
//	[uint16 len][len bytes payload] ...
//
// The length discriminates payload kinds, because no valid IP packet is shorter
// than an IPv4 header:
//
//	len == 0            legacy heartbeat (kept so a peer that only sends these
//	                    still refreshes our liveness timer)
//	0 < len < 20        control message: [opcode][operand...]
//	len >= 20           an inner IP packet, written straight to the TUN queue
//
// Batching many packets into one frame is what keeps the syscall and AEAD tag
// cost per packet low at high packet rates.

// Control opcodes.
const (
	ctlPing = 0x01 // [op][uint64 sender timestamp ns]
	ctlPong = 0x02 // [op][uint64 echoed timestamp ns]
)

// ctlLen is the wire length of a ping/pong control message.
const ctlLen = 1 + 8

// appendPacket appends one length-prefixed packet to dst.
func appendPacket(dst, pkt []byte) []byte {
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(pkt)))
	dst = append(dst, h[:]...)
	return append(dst, pkt...)
}

// appendControl appends a ping/pong control message carrying ts.
func appendControl(dst []byte, op byte, ts uint64) []byte {
	var h [2 + ctlLen]byte
	binary.BigEndian.PutUint16(h[0:2], ctlLen)
	h[2] = op
	binary.BigEndian.PutUint64(h[3:], ts)
	return append(dst, h[:]...)
}

// parseControl decodes a control payload, returning the opcode and timestamp.
func parseControl(p []byte) (op byte, ts uint64, ok bool) {
	if len(p) != ctlLen {
		return 0, 0, false
	}
	switch p[0] {
	case ctlPing, ctlPong:
		return p[0], binary.BigEndian.Uint64(p[1:]), true
	default:
		return 0, 0, false
	}
}
