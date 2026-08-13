package l3

import (
	"encoding/binary"
	"net"

	"github.com/emergency-tunnel/et/internal/config"
)

// spfCodec encodes/decodes the L4 envelope for one SPF profile. It is pure
// logic (no sockets), so it compiles and is unit-tested on every OS; the raw
// send/receive lives in spf_linux.go.
type spfCodec interface {
	network() string // raw-socket network, e.g. "ip4:icmp" / "ip4:tcp"
	proto() int      // IP protocol number (1 or 6)
	// encode appends the L4 bytes for a datagram to buf and returns the result.
	// key is the per-link id/port, tunnelPort is the fixed SPF port, reply marks
	// the listener->dialer direction. It appends rather than returning a fresh
	// slice so the caller can reuse one buffer for every packet it sends: this
	// runs once per packet, and a per-packet allocation here is CPU that could
	// have moved bytes instead.
	encode(buf []byte, spoofSrc, dst net.IP, key, tunnelPort, seq int, data []byte, reply bool) []byte
	// matchClient extracts data from an inbound packet addressed to myKey (dialer).
	matchClient(p []byte, myKey, tunnelPort int) ([]byte, bool)
	// parseServer extracts data + the sender's key from an inbound packet (listener).
	parseServer(p []byte, tunnelPort int) ([]byte, int, bool)
}

func codecFor(profile string) spfCodec {
	if profile == config.SpfProfileTCP {
		return tcpCodec{}
	}
	return icmpCodec{}
}

// ---- ICMP codec ------------------------------------------------------------

type icmpCodec struct{}

func (icmpCodec) network() string { return "ip4:icmp" }
func (icmpCodec) proto() int      { return 1 }

// The echo message is built and read through the shared framing helpers rather
// than golang.org/x/net/icmp, which allocated a message and a body per packet
// in each direction. The bytes are identical — see the framing test.
//
// Each payload also carries a direction tag, for the same reason the TUN icmp
// carrier does: the listener's kernel answers echo requests on its own, and its
// reply repeats our payload with our echo id, which is everything this codec
// matched on. The dialer accepted that mirror as if the peer had sent it, fed
// its own ciphertext to the handshake, and the link never came up — this
// profile carried no traffic at all unless echo replies were switched off
// host-wide, which also stops the server answering ping.
//
// The tunnel port follows the direction tag, for the reason in icmpframe.go: a
// raw ICMP socket receives every ICMP packet on the host, so without it two SPF
// icmp tunnels on one server read each other's frames.
func (icmpCodec) encode(buf []byte, _, _ net.IP, key, tunnelPort int, seq int, data []byte, reply bool) []byte {
	off := len(buf)
	tag := byte(tagToListener)
	if reply {
		tag = tagToDialer
	}
	buf = appendEchoHeader(buf, false, reply, key, seq)
	buf = appendTag(buf, tag, tunnelPort)
	buf = append(buf, data...)
	finishICMP(buf[off:], false)
	return buf
}

func (icmpCodec) matchClient(p []byte, myKey, tunnelPort int) ([]byte, bool) {
	data, id, ok := parseEchoMsg(p, false, true)
	if !ok || id != myKey {
		return nil, false
	}
	// Tagged for the listener means it is our own request coming back.
	return stripTag(data, tagToDialer, tunnelPort)
}

func (icmpCodec) parseServer(p []byte, tunnelPort int) ([]byte, int, bool) {
	data, id, ok := parseEchoMsg(p, false, false)
	if !ok {
		return nil, 0, false
	}
	// Also rejects ordinary ping traffic from strangers, which would otherwise
	// open a flow per source and be offered to the handshake.
	data, ok = stripTag(data, tagToListener, tunnelPort)
	if !ok {
		return nil, 0, false
	}
	return data, id, true
}

// ---- TCP codec (bare segments, no handshake) -------------------------------

type tcpCodec struct{}

func (tcpCodec) network() string { return "ip4:tcp" }
func (tcpCodec) proto() int      { return 6 }

// encode builds a minimal TCP segment: dialer uses srcPort=key,dstPort=tunnel;
// listener replies with srcPort=tunnel,dstPort=key.
func (tcpCodec) encode(buf []byte, spoofSrc, dst net.IP, key, tunnelPort, seq int, data []byte, reply bool) []byte {
	srcPort, dstPort := key, tunnelPort
	if reply {
		srcPort, dstPort = tunnelPort, key
	}
	return appendTCP(buf, spoofSrc, dst, srcPort, dstPort, uint32(seq), data)
}

func (tcpCodec) matchClient(p []byte, myKey, _ int) ([]byte, bool) {
	data, _, dstPort, ok := parseTCP(p)
	if !ok || dstPort != myKey {
		return nil, false
	}
	return data, true
}

func (tcpCodec) parseServer(p []byte, tunnelPort int) ([]byte, int, bool) {
	data, srcPort, dstPort, ok := parseTCP(p)
	if !ok || dstPort != tunnelPort {
		return nil, 0, false
	}
	return data, srcPort, true
}

// appendTCP appends a minimal TCP segment to buf. Like the icmp codec it
// appends into the caller's buffer so sending a packet allocates nothing.
func appendTCP(buf []byte, src, dst net.IP, srcPort, dstPort int, seq uint32, data []byte) []byte {
	off := len(buf)
	var hdr [20]byte
	binary.BigEndian.PutUint16(hdr[0:], uint16(srcPort))
	binary.BigEndian.PutUint16(hdr[2:], uint16(dstPort))
	binary.BigEndian.PutUint32(hdr[4:], seq)
	hdr[12] = 5 << 4 // data offset = 5 words (20 bytes), no options
	hdr[13] = 0x18   // PSH | ACK
	binary.BigEndian.PutUint16(hdr[14:], 0xffff)
	buf = append(buf, hdr[:]...)
	buf = append(buf, data...)
	seg := buf[off:]
	binary.BigEndian.PutUint16(seg[16:], tcpChecksum(src, dst, seg))
	return buf
}

func parseTCP(p []byte) (data []byte, srcPort, dstPort int, ok bool) {
	if len(p) < 20 {
		return nil, 0, 0, false
	}
	off := int(p[12]>>4) * 4
	if off < 20 || off > len(p) {
		return nil, 0, 0, false
	}
	return p[off:], int(binary.BigEndian.Uint16(p[0:])), int(binary.BigEndian.Uint16(p[2:])), true
}

func tcpChecksum(src, dst net.IP, seg []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(src.To4())
	add(dst.To4())
	var ph [4]byte
	ph[1] = 6 // protocol
	binary.BigEndian.PutUint16(ph[2:], uint16(len(seg)))
	add(ph[:])
	add(seg)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
