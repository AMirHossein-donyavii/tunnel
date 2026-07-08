// Package proxyproto builds PROXY protocol v2 headers so the exit-side service
// (Xray, nginx, ...) can see the real client address instead of the tunnel's.
package proxyproto

import (
	"encoding/binary"
	"net"
)

var signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// Header returns a PROXY protocol v2 header describing a TCP connection from
// src to dst. If the addresses are not usable TCP addresses it returns a valid
// LOCAL header (command 0x20), which downstreams treat as "no proxy info".
func Header(src, dst net.Addr) []byte {
	s, sok := src.(*net.TCPAddr)
	d, dok := dst.(*net.TCPAddr)
	if !sok || !dok {
		return localHeader()
	}
	s4, d4 := s.IP.To4(), d.IP.To4()
	if s4 != nil && d4 != nil {
		return build(0x11, s4, d4, s.Port, d.Port, 4)
	}
	return build(0x21, s.IP.To16(), d.IP.To16(), s.Port, d.Port, 16)
}

func build(famProto byte, srcIP, dstIP net.IP, srcPort, dstPort, ipLen int) []byte {
	addrLen := ipLen*2 + 4
	buf := make([]byte, 16+addrLen)
	copy(buf, signature)
	buf[12] = 0x21 // version 2, command PROXY
	buf[13] = famProto
	binary.BigEndian.PutUint16(buf[14:], uint16(addrLen))
	off := 16
	copy(buf[off:], srcIP[:ipLen])
	off += ipLen
	copy(buf[off:], dstIP[:ipLen])
	off += ipLen
	binary.BigEndian.PutUint16(buf[off:], uint16(srcPort))
	binary.BigEndian.PutUint16(buf[off+2:], uint16(dstPort))
	return buf
}

func localHeader() []byte {
	buf := make([]byte, 16)
	copy(buf, signature)
	buf[12] = 0x20 // version 2, command LOCAL
	buf[13] = 0x00 // AF_UNSPEC
	return buf
}
