// Package mux is a lightweight, flow-controlled stream multiplexer designed for
// the Emergency Tunnel reverse TCP data path. Many logical streams share a few
// long-lived, authenticated, tuned links, so a new user connection costs one
// SYN frame instead of a full TCP+crypto handshake — the key latency win on
// long-distance links.
//
// It is inspired by yamux/HTTP-2 flow control but deliberately smaller: no
// header compression, a fixed 10-byte binary frame header, per-stream receive
// windows, a two-class (priority) write scheduler, and PING-based RTT/health.
package mux

import "encoding/binary"

// Frame types.
const (
	frameData   uint8 = 0 // payload = stream data
	frameSYN    uint8 = 1 // open a stream; payload = optional destination hint
	frameWinUp  uint8 = 2 // length field = window increment (no payload)
	frameFIN    uint8 = 3 // half-close (no payload)
	frameRST    uint8 = 4 // abort stream (no payload)
	framePing   uint8 = 5 // streamID = ping id; payload = 8 opaque bytes
	frameGoAway uint8 = 6 // session shutdown; length = code
)

// Frame flags.
const (
	flagAck uint8 = 0x01 // PING: this is a reply; SYN: (reserved)
	flagPri uint8 = 0x02 // SYN: open as a high-priority stream
)

const (
	headerLen     = 10
	maxFrame      = 16 * 1024  // max DATA payload per frame
	defaultWindow = 256 * 1024 // initial per-stream receive window
	winUpdateGrip = defaultWindow / 2
)

// header is the fixed 10-byte frame header.
//
//	byte 0:      type
//	byte 1:      flags
//	bytes 2..5:  streamID (big endian)
//	bytes 6..9:  length   (big endian) — payload length, or window increment,
//	                                      or goaway code depending on type
type header [headerLen]byte

func (h *header) encode(typ, flags uint8, id, length uint32) {
	h[0] = typ
	h[1] = flags
	binary.BigEndian.PutUint32(h[2:6], id)
	binary.BigEndian.PutUint32(h[6:10], length)
}

func (h *header) typ() uint8      { return h[0] }
func (h *header) flags() uint8    { return h[1] }
func (h *header) id() uint32      { return binary.BigEndian.Uint32(h[2:6]) }
func (h *header) length() uint32  { return binary.BigEndian.Uint32(h[6:10]) }
