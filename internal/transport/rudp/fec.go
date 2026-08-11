package rudp

import (
	"encoding/binary"
	"sync"

	"github.com/klauspost/reedsolomon"
)

// Forward error correction for the reliable-UDP carrier.
//
// The ARQ underneath already recovers every lost packet, but it recovers them
// the only way a pure ARQ can: by noticing the gap and asking again. That costs
// a full round trip before the data moves, and on a long path — the one this
// project exists for — a round trip is the dominant cost of everything. A link
// with 2% loss and 100ms of latency spends far more time waiting for repairs
// than it does sending.
//
// FEC pays a fixed bandwidth premium instead of a variable latency one. Every
// group of dataShards packets is followed by parityShards computed over them,
// and any dataShards of the resulting set reconstruct the whole group. A loss
// inside a group is repaired from packets already in flight, so the receiver
// never has to ask and the sender never has to wait.
//
// It does not replace the ARQ: a group that loses more than parityShards still
// needs the retransmission, and the ARQ still provides ordering and congestion
// control. FEC only removes the round trip from the common case, which is the
// isolated loss.
//
// Parity is emitted when a group fills, so the packets of a partly-filled group
// are unprotected until enough follow them. That is the tail of a burst and the
// quiet gaps between bursts — exactly where the ARQ's retransmission is cheapest,
// because there is no queue behind the loss for it to hold up.
//
// Both ends must agree on the shard counts, exactly as they must agree on the
// pool size — a receiver that is not expecting the header cannot parse a packet
// that has one.

const (
	fecHeaderSize = 6      // seq(4) + flag(2)
	fecTypeData   = 0xF1F1 // carries a payload, delivered on arrival and coded
	fecTypeParity = 0xF2F2 // carries parity, only ever used for recovery
	fecTypeBypass = 0xF3F3 // carries a payload, delivered on arrival, never coded

	// fecPayloadPrefix is the length field prepended to a data shard's payload.
	// Reed-Solomon works on equal-sized shards, so short packets are padded to
	// the longest in their group; the length says where the real data ends.
	fecPayloadPrefix = 2

	// fecMaxGroups bounds how many recent groups are held for reconstruction.
	// A group is useful only until its packets have been repaired or given up
	// on by the ARQ, so a small window is enough and keeps memory flat under a
	// flood of forged sequence numbers.
	fecMaxGroups = 16
)

// FECParams is the shard split. Zero data shards disables FEC entirely.
type FECParams struct {
	Data   int
	Parity int
}

// Enabled reports whether these parameters describe a usable code.
func (p FECParams) Enabled() bool { return p.Data > 0 && p.Parity > 0 }

// Overhead is the fraction of extra bytes the code costs, for the panel to show
// before someone turns it on.
func (p FECParams) Overhead() float64 {
	if !p.Enabled() {
		return 0
	}
	return float64(p.Parity) / float64(p.Data)
}

// fecEncoder appends parity packets to the stream of outgoing packets.
type fecEncoder struct {
	mu     sync.Mutex
	params FECParams
	enc    reedsolomon.Encoder

	seq   uint32
	group [][]byte // data shards of the group being filled
	maxLn int      // longest shard so far, which every shard is padded to
}

func newFECEncoder(p FECParams) (*fecEncoder, error) {
	if !p.Enabled() {
		return nil, nil
	}
	enc, err := reedsolomon.New(p.Data, p.Parity)
	if err != nil {
		return nil, err
	}
	return &fecEncoder{params: p, enc: enc}, nil
}

// fecMinCoded is the smallest packet worth protecting. Reed-Solomon needs
// equal-sized shards, so every shard in a group is padded to the longest one
// and the parity is that long too. A pure acknowledgement is a couple of dozen
// bytes; letting one share a group with full-sized data makes the parity for
// that group almost entirely padding — measured, it cost more throughput than
// the retransmissions it saved, and it cost it on the acknowledgement path,
// which is the one that must stay quick.
//
// So small segments bypass the code. They are cheap to retransmit precisely
// because they are small, and they still carry a header, so the receiver never
// has to guess which framing it is holding.
const fecMinCoded = 128

// encode wraps one outgoing packet and returns everything to send: the packet
// itself, followed by the group's parity packets when it completes.
func (e *fecEncoder) encode(pkt []byte) [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(pkt) < fecMinCoded {
		// Bypass packets take no sequence number: the group arithmetic on the
		// far side is derived from the sequence, so anything outside a group
		// must not advance it.
		shard := make([]byte, fecPayloadPrefix+len(pkt))
		binary.BigEndian.PutUint16(shard, uint16(len(pkt)))
		copy(shard[fecPayloadPrefix:], pkt)
		b := make([]byte, fecHeaderSize+len(shard))
		binary.BigEndian.PutUint16(b[4:], fecTypeBypass)
		copy(b[fecHeaderSize:], shard)
		return [][]byte{b}
	}

	// The shard is the payload with its length in front, so a recovered shard
	// can be trimmed back to the bytes that were actually sent.
	shard := make([]byte, fecPayloadPrefix+len(pkt))
	binary.BigEndian.PutUint16(shard, uint16(len(pkt)))
	copy(shard[fecPayloadPrefix:], pkt)

	out := [][]byte{e.frame(fecTypeData, shard)}

	e.group = append(e.group, shard)
	if len(shard) > e.maxLn {
		e.maxLn = len(shard)
	}
	if len(e.group) < e.params.Data {
		return out
	}

	// The group is full: pad every shard to the longest, compute parity over
	// them, and send the parity packets straight after.
	shards := make([][]byte, e.params.Data+e.params.Parity)
	for i, s := range e.group {
		padded := make([]byte, e.maxLn)
		copy(padded, s)
		shards[i] = padded
	}
	for i := e.params.Data; i < len(shards); i++ {
		shards[i] = make([]byte, e.maxLn)
	}
	if err := e.enc.Encode(shards); err == nil {
		for i := e.params.Data; i < len(shards); i++ {
			out = append(out, e.frame(fecTypeParity, shards[i]))
		}
	}
	e.group = e.group[:0]
	e.maxLn = 0
	return out
}

// frame prepends the FEC header and assigns the next sequence number. Sequence
// numbers are contiguous across data and parity, which is what lets the decoder
// work out a packet's group and its position in it from the number alone.
func (e *fecEncoder) frame(typ uint16, body []byte) []byte {
	b := make([]byte, fecHeaderSize+len(body))
	binary.BigEndian.PutUint32(b, e.seq)
	binary.BigEndian.PutUint16(b[4:], typ)
	copy(b[fecHeaderSize:], body)
	e.seq++
	return b
}

// fecGroup collects the shards of one group until it can be reconstructed.
type fecGroup struct {
	index    uint32
	shards   [][]byte
	have     int
	maxLn    int
	repaired bool
}

// fecDecoder unwraps incoming packets and reconstructs the ones that were lost.
type fecDecoder struct {
	mu     sync.Mutex
	params FECParams
	enc    reedsolomon.Encoder
	groups []*fecGroup // most recent last
}

func newFECDecoder(p FECParams) (*fecDecoder, error) {
	if !p.Enabled() {
		return nil, nil
	}
	enc, err := reedsolomon.New(p.Data, p.Parity)
	if err != nil {
		return nil, err
	}
	return &fecDecoder{params: p, enc: enc}, nil
}

// decode returns the packets to hand up: the one that just arrived if it
// carried data, plus any that reconstruction recovered.
//
// A malformed or unknown packet yields nothing rather than an error. This
// carrier is a UDP port anyone can send to, and the layer above already
// authenticates every packet — dropping junk silently is both correct and the
// only behaviour that cannot be used to disrupt the tunnel from outside.
func (d *fecDecoder) decode(raw []byte) [][]byte {
	if len(raw) < fecHeaderSize {
		return nil
	}
	seq := binary.BigEndian.Uint32(raw)
	typ := binary.BigEndian.Uint16(raw[4:])
	if typ != fecTypeData && typ != fecTypeParity && typ != fecTypeBypass {
		return nil
	}
	body := raw[fecHeaderSize:]

	if typ == fecTypeBypass {
		if p, ok := trimShard(body); ok {
			return [][]byte{p}
		}
		return nil
	}

	var out [][]byte
	if typ == fecTypeData {
		// Deliver immediately. FEC must never add latency to a packet that
		// arrived intact; recovery is for the ones that did not.
		if p, ok := trimShard(body); ok {
			out = append(out, p)
		}
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	groupSize := uint32(d.params.Data + d.params.Parity)
	idx, pos := seq/groupSize, int(seq%groupSize)
	g := d.group(idx)
	if g == nil || g.repaired || g.shards[pos] != nil {
		return out
	}
	g.shards[pos] = append([]byte(nil), body...)
	g.have++
	if len(body) > g.maxLn {
		g.maxLn = len(body)
	}
	if g.have < d.params.Data {
		return out
	}

	// Enough shards are present to rebuild the group. Only the data shards that
	// never arrived are new; the rest are already upstairs.
	missing := make([]bool, groupSize)
	for i := range g.shards {
		if g.shards[i] == nil {
			missing[i] = true
			continue
		}
		if len(g.shards[i]) < g.maxLn {
			padded := make([]byte, g.maxLn)
			copy(padded, g.shards[i])
			g.shards[i] = padded
		}
	}
	if err := d.enc.Reconstruct(g.shards); err != nil {
		return out
	}
	g.repaired = true
	for i := 0; i < d.params.Data; i++ {
		if !missing[i] {
			continue
		}
		if p, ok := trimShard(g.shards[i]); ok {
			out = append(out, p)
		}
	}
	return out
}

// group returns the collector for idx, creating it if this is a group we have
// not seen and have not already moved past.
func (d *fecDecoder) group(idx uint32) *fecGroup {
	for _, g := range d.groups {
		if g.index == idx {
			return g
		}
	}
	// Ignore a group older than the window: its packets have long since been
	// delivered or retransmitted, and admitting it would let a stale or forged
	// sequence number evict a group still being filled.
	if n := len(d.groups); n > 0 && idx < d.groups[n-1].index && n >= fecMaxGroups {
		return nil
	}
	g := &fecGroup{index: idx, shards: make([][]byte, d.params.Data+d.params.Parity)}
	d.groups = append(d.groups, g)
	if len(d.groups) > fecMaxGroups {
		d.groups = d.groups[len(d.groups)-fecMaxGroups:]
	}
	return g
}

// trimShard removes the padding and the length prefix, returning the packet as
// it was handed to the encoder.
func trimShard(shard []byte) ([]byte, bool) {
	if len(shard) < fecPayloadPrefix {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(shard))
	if n == 0 || n > len(shard)-fecPayloadPrefix {
		return nil, false
	}
	return shard[fecPayloadPrefix : fecPayloadPrefix+n], true
}

// firstSegment returns the ARQ segment carried by a datagram, for the listener's
// "does this open a connection" check. With FEC on, that segment sits behind the
// FEC header, and the listener has no per-connection decoder yet for a peer it
// has not seen — but the header is fixed, so the segment can be reached without
// one. Parity packets never carry a SYN and are reported as uninteresting.
func firstSegment(raw []byte, fecOn bool) ([]byte, bool) {
	if !fecOn {
		return raw, len(raw) >= hdrLen
	}
	if len(raw) < fecHeaderSize+fecPayloadPrefix {
		return nil, false
	}
	if t := binary.BigEndian.Uint16(raw[4:]); t != fecTypeData && t != fecTypeBypass {
		return nil, false
	}
	pkt, ok := trimShard(raw[fecHeaderSize:])
	return pkt, ok && len(pkt) >= hdrLen
}
