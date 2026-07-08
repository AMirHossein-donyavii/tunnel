package l3

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// Datagram wire format over the encrypted byte-stream link:
//
//	[uint16 len][len bytes payload]
//
// A len of 0 is a heartbeat (no payload). Multiple datagrams may be written in
// one call so the AEAD layer coalesces them into as few frames as possible.
const maxPacket = 65535

// appendPacket appends one length-prefixed packet to dst.
func appendPacket(dst, pkt []byte) []byte {
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(pkt)))
	dst = append(dst, h[:]...)
	return append(dst, pkt...)
}

// appendHeartbeat appends a zero-length datagram.
func appendHeartbeat(dst []byte) []byte {
	return append(dst, 0, 0)
}

// readDatagram reads one datagram into buf. It returns the payload length
// (0 for a heartbeat) and whether it was a heartbeat.
func readDatagram(r *bufio.Reader, buf []byte) (n int, heartbeat bool, err error) {
	var h [2]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return 0, false, err
	}
	l := int(binary.BigEndian.Uint16(h[:]))
	if l == 0 {
		return 0, true, nil
	}
	if l > len(buf) {
		// Protocol violation or missized buffer: drain and report.
		_, _ = io.CopyN(io.Discard, r, int64(l))
		return 0, false, fmt.Errorf("datagram too large: %d", l)
	}
	if _, err = io.ReadFull(r, buf[:l]); err != nil {
		return 0, false, err
	}
	return l, false, nil
}
