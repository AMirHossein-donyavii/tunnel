// Package rudp implements a reliable, congestion-controlled stream over UDP.
//
// It exists so the Basic section can offer a UDP protocol: UDP alone gives no
// ordering, no retransmission and no congestion control, and the tunnel's mux
// and crypto layers both require a reliable byte stream. Rather than weaken
// those layers, this package supplies the missing guarantees underneath them —
// the same shape as TCP, but in userspace and over a single UDP flow, which is
// what lets it pass networks that throttle or block long-lived TCP.
//
// The design is a selective-repeat ARQ in the KCP tradition:
//
//   - a cumulative `una` plus an explicit ACK list, so a single loss does not
//     stall everything behind it the way a purely cumulative scheme does;
//   - Jacobson/Karels RTT estimation driving the retransmission timer;
//   - fast retransmit after a configurable number of later ACKs, so recovery
//     does not wait out an RTO;
//   - TCP-style slow start and congestion avoidance, bounded by the peer's
//     advertised receive window (flow control) as well as by cwnd.
//
// arq.go is the pure state machine: it owns no sockets and no goroutines, takes
// time as a parameter, and is therefore directly testable. conn.go wraps it in
// a net.Conn with a timer loop, and rudp.go registers the transport.
package rudp

import (
	"encoding/binary"
	"sync"
)

// Wire header. 24 bytes, fixed layout, big endian.
//
//	conv(4) cmd(1) frg(1) wnd(2) ts(4) sn(4) una(4) len(4)
const (
	hdrLen = 24

	cmdPush = 81 // carries data
	cmdAck  = 82 // acknowledges one sn
	cmdWask = 83 // window probe: "tell me your window"
	cmdWins = 84 // window advertisement (reply to wask)
	cmdSyn  = 85 // connection open
	cmdFin  = 86 // connection close
)

// Tunables. These are the defaults; newARQ callers may override the ones that
// matter per profile.
const (
	defaultMTU      = 1400
	defaultSndWnd   = 1024 // segments we may hold unacknowledged
	defaultRcvWnd   = 1024 // segments we advertise to the peer
	defaultInterval = 10   // ms between flushes

	rtoMin     = 100  // ms — floor on the retransmission timeout
	rtoDefault = 200  // ms — before the first RTT sample
	rtoMax     = 6000 // ms
	// fastResendAcks is how many later segments must be acknowledged before an
	// earlier one is assumed lost. 3 mirrors TCP's duplicate-ACK threshold: low
	// enough to recover in ~1 RTT, high enough that ordinary reordering does not
	// trigger a spurious retransmit.
	fastResendAcks = 3
	// deadLinkResends: a segment retransmitted this many times means the path is
	// gone, not congested.
	deadLinkResends = 20
)

// segment is one ARQ unit, in flight or queued.
type segment struct {
	conv     uint32
	cmd      uint8
	frg      uint8
	wnd      uint16
	ts       uint32
	sn       uint32
	una      uint32
	data     []byte
	resendTs uint32 // when to retransmit
	rto      uint32 // this segment's timeout (doubles per resend)
	fastAck  uint32 // how many later segments have been acknowledged
	xmit     uint32 // transmission count
	rtoXmit  uint32 // transmissions caused by a timeout, not by a fast retransmit
}

func (s *segment) encode(b []byte) int {
	binary.BigEndian.PutUint32(b[0:], s.conv)
	b[4] = s.cmd
	b[5] = s.frg
	binary.BigEndian.PutUint16(b[6:], s.wnd)
	binary.BigEndian.PutUint32(b[8:], s.ts)
	binary.BigEndian.PutUint32(b[12:], s.sn)
	binary.BigEndian.PutUint32(b[16:], s.una)
	binary.BigEndian.PutUint32(b[20:], uint32(len(s.data)))
	copy(b[hdrLen:], s.data)
	return hdrLen + len(s.data)
}

// ack is one pending acknowledgement.
type ack struct{ sn, ts uint32 }

// ARQ is the reliable-stream state machine for one connection.
//
// All methods take the current time in milliseconds so the caller owns the
// clock; nothing here sleeps, allocates goroutines or touches a socket.
type ARQ struct {
	mu sync.Mutex

	conv   uint32
	mtu    uint32
	mss    uint32
	dead   bool
	closed bool

	sndUna, sndNxt, rcvNxt uint32
	ssthresh               uint32
	rxRttval, rxSrtt       int32
	rxRto                  uint32
	probeWait              uint32

	sndWnd, rcvWnd, rmtWnd uint32
	cwnd                   uint32
	fecData, fecParity     uint32 // parity the layer below adds per data group
	incr                   uint32

	interval uint32
	tsFlush  uint32

	// nodelay mode: retransmit timeouts grow by 1.5x instead of 2x and the
	// congestion window is not halved as harshly. The gaming profile turns this
	// on; bulk profiles leave it off.
	nodelay bool

	sndQueue []*segment // waiting for window
	sndBuf   []*segment // sent, unacknowledged
	rcvBuf   []*segment // received out of order
	rcvQueue []*segment // in order, ready for the reader
	ackList  []ack

	probe  uint32
	output func([]byte) // called with a full datagram to transmit
}

const (
	probeNeedSend = 1
	probeNeedTell = 2
)

func newARQ(conv uint32, output func([]byte)) *ARQ {
	return &ARQ{
		conv:   conv,
		mtu:    defaultMTU,
		mss:    defaultMTU - hdrLen,
		sndWnd: defaultSndWnd,
		rcvWnd: defaultRcvWnd,
		rmtWnd: defaultRcvWnd,
		cwnd:   1,
		// Slow start must actually run: starting ssthresh at a small constant
		// drops straight into congestion avoidance, which opens the window by
		// roughly one segment per RTT and caps a loopback transfer at single-digit
		// Mbit/s. TCP starts it effectively unbounded; the receive window is the
		// real ceiling here.
		ssthresh: defaultRcvWnd,
		rxRto:    rtoDefault,
		interval: defaultInterval,
		output:   output,
	}
}

// SetNoDelay switches to the latency-oriented timer behaviour.
func (a *ARQ) SetNoDelay(on bool, intervalMS uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nodelay = on
	if intervalMS > 0 {
		a.interval = intervalMS
	}
}

// SetWindow sets the send and advertised receive windows in segments.
func (a *ARQ) SetWindow(snd, rcv uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if snd > 0 {
		a.sndWnd = snd
	}
	if rcv > 0 {
		a.rcvWnd = rcv
		a.rmtWnd = rcv
		if a.ssthresh < rcv {
			a.ssthresh = rcv
		}
	}
}

// SetMTU adjusts the datagram size; the payload per segment follows.
func (a *ARQ) SetMTU(mtu uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if mtu > hdrLen+64 {
		a.mtu = mtu
		a.mss = mtu - hdrLen
	}
}

// wndUnused is how many segments of receive window remain.
func (a *ARQ) wndUnused() uint16 {
	if uint32(len(a.rcvQueue)) < a.rcvWnd {
		return uint16(a.rcvWnd - uint32(len(a.rcvQueue)))
	}
	return 0
}

// QueueLimit is the send-queue ceiling in segments. Without one, Write accepts
// data at memory speed while the wire carries only cwnd per round trip: the
// queue grows without bound (half a gigabyte in three seconds, measured), the
// UDP socket buffer overflows, the resulting loss collapses cwnd, and the
// layer above sees a throughput figure that is pure buffering. Bounding it
// turns Write into real backpressure, which is what the mux above expects.
func (a *ARQ) QueueLimit() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return int(a.sndWnd) * 4
}

// SendQueued reports the segments waiting for window.
func (a *ARQ) SendQueued() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.sndQueue)
}

// Send queues application bytes, splitting them into MSS-sized segments. It
// accepts only what fits the queue limit and returns how much it took, so the
// caller can wait and retry rather than buffering without bound.
func (a *ARQ) Send(b []byte) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	limit := int(a.sndWnd) * 4
	n := 0
	for len(b) > 0 {
		if len(a.sndQueue) >= limit {
			break
		}
		size := len(b)
		if uint32(size) > a.mss {
			size = int(a.mss)
		}
		seg := &segment{conv: a.conv, cmd: cmdPush, data: append([]byte(nil), b[:size]...)}
		a.sndQueue = append(a.sndQueue, seg)
		b = b[size:]
		n += size
	}
	return n
}

// Recv copies in-order bytes into b, returning how many were delivered.
func (a *ARQ) Recv(b []byte) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for len(a.rcvQueue) > 0 && n < len(b) {
		seg := a.rcvQueue[0]
		c := copy(b[n:], seg.data)
		n += c
		if c < len(seg.data) {
			// Partially consumed: keep the remainder at the head.
			seg.data = seg.data[c:]
			break
		}
		a.rcvQueue = a.rcvQueue[1:]
	}
	// Consuming from the queue frees receive window, which the peer learns from
	// the next segment we send.
	a.moveToQueue()
	return n
}

// PendingRecv reports whether Recv would return data.
func (a *ARQ) PendingRecv() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.rcvQueue) > 0
}

// Dead reports that the peer stopped responding (repeated retransmit failure)
// or sent FIN.
func (a *ARQ) Dead() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dead
}

func (a *ARQ) markDead() {
	a.mu.Lock()
	a.dead = true
	a.mu.Unlock()
}

// ---- receive path ----------------------------------------------------------

// Input feeds one received datagram into the state machine.
func (a *ARQ) Input(data []byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(data) < hdrLen {
		return false
	}
	oldUna := a.sndUna
	inflightBefore := uint32(len(a.sndBuf))
	var maxAck uint32
	var ackedAny bool

	for len(data) >= hdrLen {
		conv := binary.BigEndian.Uint32(data[0:])
		if conv != a.conv {
			return false
		}
		cmd := data[4]
		wnd := binary.BigEndian.Uint16(data[6:])
		ts := binary.BigEndian.Uint32(data[8:])
		sn := binary.BigEndian.Uint32(data[12:])
		una := binary.BigEndian.Uint32(data[16:])
		length := binary.BigEndian.Uint32(data[20:])
		if uint32(len(data)-hdrLen) < length {
			return false
		}
		payload := data[hdrLen : hdrLen+length]
		data = data[hdrLen+length:]

		a.rmtWnd = uint32(wnd)
		a.parseUna(una)
		a.shrinkSndBuf()

		switch cmd {
		case cmdAck:
			a.parseAck(sn)
			a.updateRTT(ts)
			if !ackedAny || sn > maxAck {
				maxAck, ackedAny = sn, true
			}
			a.shrinkSndBuf()
		case cmdSyn:
			// A SYN opens the connection; it carries no stream data and must NOT
			// consume a sequence number.
			//
			// It used to be handled as data. Its sn is 0, so it took slot 0 of the
			// receive stream and advanced rcvNxt to 1 — and then the first real
			// segment, whose sn is also 0 because the sender starts there, was
			// rejected as already seen and acknowledged anyway, so it was never
			// resent. Every connection established perfectly and then carried
			// nothing in that direction: the tunnel's handshake timed out on one
			// side and read EOF on the other. Acknowledge it and deliver nothing.
			a.ackList = append(a.ackList, ack{sn: sn, ts: ts})
		case cmdPush:
			// Only accept what fits the advertised window; anything beyond it is
			// the peer ignoring flow control.
			if sn < a.rcvNxt+a.rcvWnd {
				a.ackList = append(a.ackList, ack{sn: sn, ts: ts})
				if sn >= a.rcvNxt {
					a.parseData(&segment{conv: conv, cmd: cmd, sn: sn, ts: ts,
						data: append([]byte(nil), payload...)})
				}
			}
		case cmdFin:
			a.dead = true
		case cmdWask:
			a.probe |= probeNeedTell
		case cmdWins:
			// window already recorded above
		default:
			return false
		}
	}

	if ackedAny {
		a.parseFastAck(maxAck)
	}
	// Congestion window growth is per acknowledged segment, which is what makes
	// slow start actually double the window each round trip.
	if a.sndUna > oldUna && a.cwnd < a.rmtWnd {
		acked := int(inflightBefore) - len(a.sndBuf)
		if acked < 1 {
			acked = 1
		}
		for i := 0; i < acked && a.cwnd < a.rmtWnd; i++ {
			a.growCwnd()
		}
	}
	return true
}

// parseUna drops everything the peer has cumulatively acknowledged.
func (a *ARQ) parseUna(una uint32) {
	keep := a.sndBuf[:0]
	for _, s := range a.sndBuf {
		if s.sn < una {
			continue
		}
		keep = append(keep, s)
	}
	a.sndBuf = keep
	if una > a.sndUna {
		a.sndUna = una
	}
}

// parseAck removes one selectively acknowledged segment.
func (a *ARQ) parseAck(sn uint32) {
	if sn < a.sndUna || sn >= a.sndNxt {
		return
	}
	for i, s := range a.sndBuf {
		if s.sn == sn {
			a.sndBuf = append(a.sndBuf[:i], a.sndBuf[i+1:]...)
			return
		}
		if s.sn > sn {
			return
		}
	}
}

// parseFastAck counts, for every unacknowledged segment, how many later
// segments have been acknowledged — the fast-retransmit trigger.
func (a *ARQ) parseFastAck(sn uint32) {
	for _, s := range a.sndBuf {
		if s.sn > sn {
			break
		}
		if s.sn != sn {
			s.fastAck++
		}
	}
}

// shrinkSndBuf advances sndUna to the first still-unacknowledged segment.
func (a *ARQ) shrinkSndBuf() {
	if len(a.sndBuf) > 0 {
		a.sndUna = a.sndBuf[0].sn
	} else {
		a.sndUna = a.sndNxt
	}
}

// parseData inserts a received segment in order, ignoring duplicates.
func (a *ARQ) parseData(newSeg *segment) {
	sn := newSeg.sn
	if sn >= a.rcvNxt+a.rcvWnd || sn < a.rcvNxt {
		return
	}
	// Insert sorted; drop an exact duplicate.
	pos := len(a.rcvBuf)
	for i := len(a.rcvBuf) - 1; i >= 0; i-- {
		s := a.rcvBuf[i]
		if s.sn == sn {
			return
		}
		if sn > s.sn {
			break
		}
		pos = i
	}
	a.rcvBuf = append(a.rcvBuf, nil)
	copy(a.rcvBuf[pos+1:], a.rcvBuf[pos:])
	a.rcvBuf[pos] = newSeg
	a.moveToQueue()
}

// moveToQueue promotes contiguous segments from the reorder buffer to the
// reader's queue.
func (a *ARQ) moveToQueue() {
	count := 0
	for _, s := range a.rcvBuf {
		if s.sn != a.rcvNxt || uint32(len(a.rcvQueue)) >= a.rcvWnd {
			break
		}
		a.rcvQueue = append(a.rcvQueue, s)
		a.rcvNxt++
		count++
	}
	if count > 0 {
		a.rcvBuf = a.rcvBuf[count:]
	}
}

// ---- RTT / congestion ------------------------------------------------------

// updateRTT is Jacobson/Karels: smoothed RTT plus mean deviation, with the RTO
// clamped so a single outlier cannot stall the connection for seconds.
func (a *ARQ) updateRTT(ts uint32) {
	rtt := int32(a.tsFlush - ts)
	if rtt < 0 {
		return
	}
	if a.rxSrtt == 0 {
		a.rxSrtt = rtt
		a.rxRttval = rtt / 2
	} else {
		delta := rtt - a.rxSrtt
		if delta < 0 {
			delta = -delta
		}
		a.rxRttval = (3*a.rxRttval + delta) / 4
		a.rxSrtt = (7*a.rxSrtt + rtt) / 8
		if a.rxSrtt < 1 {
			a.rxSrtt = 1
		}
	}
	rto := uint32(a.rxSrtt) + max32(a.interval, uint32(4*a.rxRttval))
	a.rxRto = bound32(rtoMin, rto, rtoMax)
}

// growCwnd is TCP-style: exponential below ssthresh, roughly one segment per
// RTT above it.
func (a *ARQ) growCwnd() {
	if a.cwnd < a.ssthresh {
		a.cwnd++
		a.incr += a.mss
		return
	}
	if a.incr < a.mss {
		a.incr = a.mss
	}
	a.incr += (a.mss*a.mss)/a.incr + (a.mss / 16)
	if (a.cwnd+1)*a.mss <= a.incr {
		a.cwnd = (a.incr + a.mss - 1) / max32(a.mss, 1)
	}
	if a.cwnd > a.rmtWnd {
		a.cwnd = a.rmtWnd
		a.incr = a.rmtWnd * a.mss
	}
}

// onLoss reacts to a retransmission timeout: the classic multiplicative
// decrease, all the way back to slow start.
func (a *ARQ) onLoss() {
	a.ssthresh = max32(a.cwnd/2, 2)
	a.cwnd = 1
	a.incr = a.mss
}

// onFastResend reacts to a fast retransmit: halve, but keep sending.
func (a *ARQ) onFastResend(inflight uint32) {
	a.ssthresh = max32(inflight/2, 2)
	if a.nodelay {
		// Latency mode gives up less window: a game's flow is small and a hard
		// cut costs more in delay than it saves in congestion.
		a.cwnd = max32(a.ssthresh, a.cwnd*3/4)
	} else {
		a.cwnd = a.ssthresh + fastResendAcks
	}
	a.incr = a.cwnd * a.mss
}

// ---- transmit path ---------------------------------------------------------

// Update runs the timer-driven half: acknowledgements, new data, retransmits.
// current is milliseconds from an arbitrary but monotonic origin.
func (a *ARQ) Update(current uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tsFlush = current
	a.flush(current)
}

// Interval is the flush period in milliseconds.
func (a *ARQ) Interval() uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.interval
}

// flush emits everything due at `current`. Caller holds mu.
func (a *ARQ) flush(current uint32) {
	buf := make([]byte, 0, a.mtu)
	seg := segment{conv: a.conv, wnd: a.wndUnused(), una: a.rcvNxt}

	emit := func(s *segment) {
		if len(buf)+hdrLen+len(s.data) > int(a.mtu) {
			a.output(buf)
			buf = buf[:0]
		}
		need := hdrLen + len(s.data)
		start := len(buf)
		buf = append(buf, make([]byte, need)...)
		s.encode(buf[start:])
	}

	// 1. Acknowledgements first — they are what unblocks the peer.
	for _, ac := range a.ackList {
		seg.cmd = cmdAck
		seg.sn, seg.ts, seg.data = ac.sn, ac.ts, nil
		emit(&seg)
	}
	a.ackList = a.ackList[:0]

	// 2. Window probing. A peer whose window is closed must be asked again, or
	//    both sides wait forever for the other.
	if a.rmtWnd == 0 {
		if a.probeWait == 0 {
			a.probeWait = 7000
		}
		a.probe |= probeNeedSend
	} else {
		a.probeWait = 0
	}
	if a.probe&probeNeedSend != 0 {
		seg.cmd = cmdWask
		seg.sn, seg.ts, seg.data = 0, 0, nil
		emit(&seg)
	}
	if a.probe&probeNeedTell != 0 {
		seg.cmd = cmdWins
		seg.sn, seg.ts, seg.data = 0, 0, nil
		emit(&seg)
	}
	a.probe = 0

	// 3. Move queued data into flight, bounded by BOTH the congestion window
	//    (what the path can take) and the peer's advertised window (what the
	//    peer can hold). Ignoring either is how a tunnel collapses under load.
	cwnd := min32(a.sndWnd, a.rmtWnd)
	cwnd = min32(cwnd, a.cwnd)
	cwnd = a.codedWindow(cwnd)
	if cwnd < 1 {
		cwnd = 1
	}
	for a.sndNxt < a.sndUna+cwnd && len(a.sndQueue) > 0 {
		s := a.sndQueue[0]
		a.sndQueue = a.sndQueue[1:]
		s.conv, s.cmd, s.wnd, s.ts = a.conv, cmdPush, seg.wnd, current
		s.sn, s.una = a.sndNxt, a.rcvNxt
		s.resendTs, s.rto = current, a.rxRto
		a.sndNxt++
		a.sndBuf = append(a.sndBuf, s)
	}

	// 4. Transmit and retransmit.
	var lost, fastResend bool
	inflight := uint32(len(a.sndBuf))
	for _, s := range a.sndBuf {
		send := false
		switch {
		case s.xmit == 0: // first transmission
			send = true
			s.rto = a.rxRto
			s.resendTs = current + s.rto
		case current >= s.resendTs: // timeout
			send = true
			s.rtoXmit++
			if a.nodelay {
				s.rto += s.rto / 2
			} else {
				s.rto += s.rto
			}
			s.rto = min32(s.rto, rtoMax)
			s.resendTs = current + s.rto
			lost = true
		case s.fastAck >= fastResendAcks: // fast retransmit
			send = true
			s.fastAck = 0
			s.resendTs = current + s.rto
			fastResend = true
		}
		if !send {
			continue
		}
		s.xmit++
		s.ts = current
		s.wnd = seg.wnd
		s.una = a.rcvNxt
		emit(s)
		// Only timeouts count toward "the path is gone".
		//
		// This counted every transmission, fast retransmits included, which was
		// survivable only while flushing was throttled to one pass per interval
		// tick. Once arrivals drive the flush, a segment being recovered on a
		// busy link can be fast-retransmitted many times within a few
		// milliseconds and trip the limit — and a fast retransmit is triggered by
		// acknowledgements arriving, which is positive proof the path is alive.
		// A path that is really gone stops acknowledging, and then it is the RTO
		// that fires, over and over, which is what this counts now.
		if s.rtoXmit >= deadLinkResends {
			a.dead = true
		}
	}

	if len(buf) > 0 {
		a.output(buf)
	}
	if fastResend {
		a.onFastResend(inflight)
	}
	if lost {
		a.onLoss()
	}
}

// SendFIN queues a connection-close notice.
func (a *ARQ) SendFIN() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	a.closed = true
	s := &segment{conv: a.conv, cmd: cmdFin, wnd: a.wndUnused(), una: a.rcvNxt}
	b := make([]byte, hdrLen)
	s.encode(b)
	a.output(b)
}

// Stats exposes the counters worth surfacing on a dashboard.
func (a *ARQ) Stats() (cwnd, inflight, queued, srtt, rto uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cwnd, uint32(len(a.sndBuf)), uint32(len(a.sndQueue)), uint32(a.rxSrtt), a.rxRto
}

func max32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}
func min32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
func bound32(lo, v, hi uint32) uint32 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// SetFECOverhead tells the ARQ that the layer beneath it turns every data
// packets into data+parity packets on the wire.
//
// Without this the congestion window means the wrong thing. It is sized against
// what the path will carry, and the encoder then adds parity to that same path
// without the window knowing — so the connection sends more than it measured the
// path can take, and the extra displaces exactly the data the parity exists to
// protect. Measured, that made error correction a net loss at every loss rate.
func (a *ARQ) SetFECOverhead(data, parity int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if data <= 0 || parity <= 0 {
		a.fecData, a.fecParity = 0, 0
		return
	}
	a.fecData, a.fecParity = uint32(data), uint32(parity)
}

// codedWindow scales a window down by the share of it parity will occupy, so
// that data plus parity together stay inside what congestion control allows.
func (a *ARQ) codedWindow(w uint32) uint32 {
	if a.fecData == 0 || a.fecParity == 0 {
		return w
	}
	return w * a.fecData / (a.fecData + a.fecParity)
}
