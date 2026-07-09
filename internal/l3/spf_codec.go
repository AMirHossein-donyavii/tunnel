package l3

import (
	"encoding/binary"
	"net"

	"github.com/emergency-tunnel/et/internal/config"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// spfCodec encodes/decodes the L4 envelope for one SPF profile. It is pure
// logic (no sockets), so it compiles and is unit-tested on every OS; the raw
// send/receive lives in spf_linux.go.
type spfCodec interface {
	network() string // raw-socket network, e.g. "ip4:icmp" / "ip4:tcp"
	proto() int      // IP protocol number (1 or 6)
	// encode builds the L4 bytes for a datagram. key is the per-link id/port,
	// tunnelPort is the fixed SPF port, reply marks the listener->dialer direction.
	encode(spoofSrc, dst net.IP, key, tunnelPort, seq int, data []byte, reply bool) ([]byte, error)
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

func (icmpCodec) encode(_, _ net.IP, key, _ int, seq int, data []byte, reply bool) ([]byte, error) {
	typ := icmp.Type(ipv4.ICMPTypeEcho)
	if reply {
		typ = ipv4.ICMPTypeEchoReply
	}
	m := icmp.Message{Type: typ, Code: 0, Body: &icmp.Echo{ID: key, Seq: seq, Data: data}}
	return m.Marshal(nil)
}

func (icmpCodec) matchClient(p []byte, myKey, _ int) ([]byte, bool) {
	m, err := icmp.ParseMessage(1, p)
	if err != nil || m.Type != ipv4.ICMPTypeEchoReply {
		return nil, false
	}
	e, ok := m.Body.(*icmp.Echo)
	if !ok || e.ID != myKey {
		return nil, false
	}
	return e.Data, true
}

func (icmpCodec) parseServer(p []byte, _ int) ([]byte, int, bool) {
	m, err := icmp.ParseMessage(1, p)
	if err != nil || m.Type != ipv4.ICMPTypeEcho {
		return nil, 0, false
	}
	e, ok := m.Body.(*icmp.Echo)
	if !ok {
		return nil, 0, false
	}
	return e.Data, e.ID, true
}

// ---- TCP codec (bare segments, no handshake) -------------------------------

type tcpCodec struct{}

func (tcpCodec) network() string { return "ip4:tcp" }
func (tcpCodec) proto() int      { return 6 }

// encode builds a minimal TCP segment: dialer uses srcPort=key,dstPort=tunnel;
// listener replies with srcPort=tunnel,dstPort=key.
func (tcpCodec) encode(spoofSrc, dst net.IP, key, tunnelPort, seq int, data []byte, reply bool) ([]byte, error) {
	srcPort, dstPort := key, tunnelPort
	if reply {
		srcPort, dstPort = tunnelPort, key
	}
	return buildTCP(spoofSrc, dst, srcPort, dstPort, uint32(seq), data), nil
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

func buildTCP(src, dst net.IP, srcPort, dstPort int, seq uint32, data []byte) []byte {
	seg := make([]byte, 20+len(data))
	binary.BigEndian.PutUint16(seg[0:], uint16(srcPort))
	binary.BigEndian.PutUint16(seg[2:], uint16(dstPort))
	binary.BigEndian.PutUint32(seg[4:], seq)
	seg[12] = 5 << 4 // data offset = 5 words (20 bytes), no options
	seg[13] = 0x18   // PSH | ACK
	binary.BigEndian.PutUint16(seg[14:], 0xffff)
	copy(seg[20:], data)
	binary.BigEndian.PutUint16(seg[16:], tcpChecksum(src, dst, seg))
	return seg
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
