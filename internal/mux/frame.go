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
	headerLen = 10
	maxFrame  = 16 * 1024 // max DATA payload per frame
	// writeBatch bounds how many bytes the writer coalesces into one Write.
	//
	// It is a latency/throughput trade: a bigger batch means fewer syscalls, but
	// a high-priority frame produced while the writer is blocked pushing the
	// batch out has to wait for the whole batch to drain first. 32 KiB is one
	// AEAD frame on the encrypted link (so a full batch is exactly one write and
	// one seal) and bounds that wait to a few milliseconds even on a slow path,
	// while still being large enough that syscall cost is negligible at any rate
	// this tunnel runs at.
	writeBatch = 32 * 1024
	// defaultWindow is the fallback initial per-stream receive window when the
	// session Config does not set one. It caps the bandwidth-delay product a
	// single stream can fill while only costing RAM for bytes actually in flight
	// (idle streams use ~0). The engine raises this per performance profile; the
	// WINDOW_UPDATE threshold is derived as window/2 per stream.
	defaultWindow = 2 * 1024 * 1024
	// maxRecvBuffer is the hard per-stream receive-buffer ceiling. It is set well
	// above the largest profile window (fast = 4 MiB) so a conformant, in-window
	// peer never reaches it; it only bounds memory against a peer that ignores
	// flow control (the receiver appends delivered data before the app reads it).
	maxRecvBuffer = 16 * 1024 * 1024
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

func (h *header) typ() uint8     { return h[0] }
func (h *header) flags() uint8   { return h[1] }
func (h *header) id() uint32     { return binary.BigEndian.Uint32(h[2:6]) }
func (h *header) length() uint32 { return binary.BigEndian.Uint32(h[6:10]) }
