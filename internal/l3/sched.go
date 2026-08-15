package l3

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// The TUN transmit path is the tunnel's queueing point: the kernel hands us
// packets as fast as the local NIC can produce them, while the carrier drains
// them at whatever rate the Iran<->Kharej path allows. Everything that makes a
// tunnel feel bad — a ping that jumps from 97 ms to 400 ms, a download that
// stalls, an SSH session that goes numb during a file transfer — happens in
// that gap. A plain FIFO channel makes it worse: a full 256-packet queue is
// ~350 KB of standing backlog, and on a 20 Mbit path that is 140 ms of delay
// added to *every* packet, interactive or not.
//
// txQueue replaces the FIFO with the two mechanisms that actually fix this:
//
//   - Two service classes. Latency-critical packets (ICMP, DNS, pure TCP ACKs,
//     handshakes, small datagrams) go to an express ring that is always drained
//     first, so they never wait behind a bulk transfer's backlog.
//   - CoDel AQM (RFC 8289) on the bulk ring. Instead of letting the backlog
//     grow until the queue is full, CoDel watches how long packets actually sit
//     in the queue and starts dropping when the *sojourn time* stays above 5 ms
//     for a full interval. Inner TCP reads those drops as the congestion signal
//     it is waiting for and settles at a rate that keeps the queue short — full
//     throughput, no standing delay.
//
// Packet buffers are pooled and handed back after the batch is framed, so the
// steady-state hot path allocates nothing.

const (
	// codelTarget is the queue sojourn time CoDel aims to keep the bulk class
	// under. 5 ms is the RFC-recommended value and is well below the tunnel's own
	// RTT, so it constrains only queueing delay, never the path.
	codelTarget = 5 * time.Millisecond
	// codelInterval is roughly a worst-case RTT: the queue must stay above target
	// for this long before dropping starts, which keeps CoDel from reacting to
	// ordinary bursts.
	codelInterval = 100 * time.Millisecond
	// expressStale bounds how long a latency-critical packet may wait before it
	// is considered overtaken.
	//
	// It used to be 250 ms and unconditional, which manufactured the very symptom
	// it was meant to avoid: a carrier hiccup of a third of a second turned a
	// ping through the tunnel into a timeout, when delivering it would have shown
	// an honest 300 ms. The same drop costs a pure TCP ACK a full retransmission
	// timeout on the peer.
	//
	// Two changes. The bound is a second, which is past the point where a voice
	// or game packet is genuinely worthless; and a stale packet is only dropped
	// when there is a fresher express packet behind it, since the whole
	// justification for dropping — that something better is waiting — is false
	// when the queue is empty.
	expressStale = time.Second
	// expressCap bounds the express ring. Express traffic is small and drained
	// first, so this is only a guard against a flood of tiny packets.
	expressCap = 512

	// There is deliberately no hard ceiling on bulk queueing delay here.
	//
	// One was added and removed again. It dropped any bulk packet older than a
	// fixed age at dequeue, which sounds like a bound on latency and is in fact a
	// way to destroy the whole queue: the check ran in a loop, so the first pop
	// after the queue had ever been backed up past the ceiling discarded every
	// packet in it, and then did the same on the next pop. Inner TCP retransmits
	// what was lost, the queue refills, and it is purged again — measured on a
	// real path at 3 Mbit/s where the same tunnel without it did 121.
	//
	// CoDel already bounds the *standing* queue, and it does it by dropping at a
	// rate rather than in bulk, which is the difference between a congestion
	// signal and a wipe. If the standing queue is still too deep, the answer is
	// in how CoDel is driven — not a second dropper competing with it.
)

// classifier thresholds.
const (
	// minIPPacket is the smallest valid IP header. Shorter payloads on the wire
	// are tunnel control frames, never packets.
	minIPPacket = 20
	// smallPacket is the size below which any packet is treated as interactive.
	smallPacket = 128
	// udpExpressMax is the largest UDP datagram sent express. UDP has no
	// ordering guarantee, so expediting small datagrams (DNS, QUIC ACKs, VoIP,
	// game traffic, WireGuard handshakes) is always safe.
	udpExpressMax = 192
)

// pbuf is a pooled packet buffer. n is the valid prefix length; enq is the
// monotonic nanosecond timestamp used by CoDel to measure queue sojourn.
type pbuf struct {
	b   []byte
	n   int
	enq int64
}

func (p *pbuf) bytes() []byte { return p.b[:p.n] }

// bufPool recycles packet buffers of exactly pktLen bytes.
type bufPool struct {
	pool   sync.Pool
	pktLen int
}

func newBufPool(pktLen int) *bufPool {
	bp := &bufPool{pktLen: pktLen}
	bp.pool.New = func() any { return &pbuf{b: make([]byte, pktLen)} }
	return bp
}

func (bp *bufPool) get() *pbuf {
	p := bp.pool.Get().(*pbuf)
	p.n = 0
	return p
}

func (bp *bufPool) put(p *pbuf) {
	if p == nil || cap(p.b) < bp.pktLen {
		return
	}
	p.b = p.b[:bp.pktLen]
	bp.pool.Put(p)
}

// ring is a fixed-capacity FIFO of packet buffers backed by a circular slice.
type ring struct {
	buf  []*pbuf
	head int
	size int
}

func newRing(capacity int) ring { return ring{buf: make([]*pbuf, capacity)} }

func (r *ring) len() int   { return r.size }
func (r *ring) full() bool { return r.size == len(r.buf) }

func (r *ring) push(p *pbuf) bool {
	if r.full() {
		return false
	}
	r.buf[(r.head+r.size)%len(r.buf)] = p
	r.size++
	return true
}

func (r *ring) pop() *pbuf {
	if r.size == 0 {
		return nil
	}
	p := r.buf[r.head]
	r.buf[r.head] = nil
	r.head = (r.head + 1) % len(r.buf)
	r.size--
	return p
}

// qstats are the per-queue counters surfaced on the health endpoint.
type qstats struct {
	expressPkts atomic.Uint64
	bulkPkts    atomic.Uint64
	// Three different drops with three different meanings, counted apart
	// because a diagnosis needs to tell them from each other: AQM dropping to
	// signal congestion is the system working, a full ring is the system out of
	// room, and a stale express packet is one that was overtaken. They were one
	// counter, which made a health line that could not answer the only question
	// it was there to answer.
	dropped   atomic.Uint64 // total, for compatibility
	aqmDrop   atomic.Uint64 // CoDel, deliberately spaced congestion signal
	fullDrop  atomic.Uint64 // ring had no room: a burst lost at once
	staleDrop atomic.Uint64 // express packet overtaken by a fresher one
	depth     atomic.Int64  // current bulk+express packets
}

// codel holds the RFC 8289 controller state for one bulk ring.
type codel struct {
	firstAbove int64 // ns; when the sojourn first exceeded target (0 = below)
	dropNext   int64 // ns; when the next drop is due while dropping
	count      uint32
	lastCount  uint32
	dropping   bool
}

// txQueue is one TUN queue's transmit scheduler: express + CoDel-managed bulk.
// It has one producer (the TUN reader) and one consumer (the link writer).
// aqmOff turns the bulk ring into a plain tail-drop FIFO. See Config.AQM: CoDel
// spaces its drops, and a single bulk flow reads each spaced drop as its own
// congestion event, so on a long path with one heavy flow it can cost
// throughput that a queue losing a burst at once does not.
type txQueue struct {
	aqmOff bool

	mu       sync.Mutex
	express  ring
	bulk     ring
	bytes    int // bulk bytes currently queued
	maxBytes int
	mtu      int
	codel    codel

	notify chan struct{} // cap 1: consumer wakeup
	pool   *bufPool
	stats  *qstats
	now    func() int64 // injectable clock (ns) for tests
}

func newTxQueue(depth, mtu int, pool *bufPool, stats *qstats) *txQueue {
	return newTxQueueAQM(depth, mtu, pool, stats, true)
}

func newTxQueueAQM(depth, mtu int, pool *bufPool, stats *qstats, codel bool) *txQueue {
	if depth < 16 {
		depth = 16
	}
	return &txQueue{
		aqmOff:   !codel,
		express:  newRing(expressCap),
		bulk:     newRing(depth),
		maxBytes: depth * mtu,
		mtu:      mtu,
		notify:   make(chan struct{}, 1),
		pool:     pool,
		stats:    stats,
		now:      func() int64 { return time.Now().UnixNano() },
	}
}

// signal is the channel a consumer selects on to wait for work.
func (q *txQueue) signal() <-chan struct{} { return q.notify }

func (q *txQueue) wake() {
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

// push enqueues a packet, classifying it into the express or bulk class. On
// overflow the packet is dropped (tail drop) — CoDel governs latency long
// before the hard cap is reached, so hitting it means the carrier is genuinely
// saturated and shedding the newest packet is the correct congestion signal.
func (q *txQueue) push(p *pbuf) {
	p.enq = q.now()
	express := isExpress(p.bytes())

	q.mu.Lock()
	var ok bool
	if express {
		ok = q.express.push(p)
	} else if q.bytes+p.n <= q.maxBytes {
		if ok = q.bulk.push(p); ok {
			q.bytes += p.n
		}
	}
	depth := q.express.len() + q.bulk.len()
	q.mu.Unlock()

	if !ok {
		// No room: this is the queue being full, not the AQM choosing to signal.
		q.stats.dropped.Add(1)
		q.stats.fullDrop.Add(1)
		q.pool.put(p)
		return
	}
	if express {
		q.stats.expressPkts.Add(1)
	} else {
		q.stats.bulkPkts.Add(1)
	}
	q.stats.depth.Store(int64(depth))
	q.wake()
}

// pop returns the next packet to transmit, or nil when the queue is empty.
// Express packets go first; bulk packets pass through the CoDel controller.
func (q *txQueue) pop() *pbuf {
	now := q.now()
	q.mu.Lock()
	defer q.mu.Unlock()

	// Express first, skipping anything stale that something fresher is waiting
	// behind.
	for {
		p := q.express.pop()
		if p == nil {
			break
		}
		if now-p.enq <= int64(expressStale) || q.express.len() == 0 {
			q.stats.depth.Store(int64(q.express.len() + q.bulk.len()))
			q.wakeIfWork()
			return p
		}
		q.dropStale(p)
	}

	var p *pbuf
	if q.aqmOff {
		// Plain FIFO: the only drops are the ones push() already made when the
		// ring was full, which is a burst lost at once.
		p = q.bulkPop()
	} else {
		p = q.codelDequeue(now)
	}
	q.stats.depth.Store(int64(q.express.len() + q.bulk.len()))
	q.wakeIfWork()
	return p
}

// wakeIfWork hands the wakeup on to another consumer when packets remain.
//
// push() signals through a channel of capacity one, which is all a single
// consumer needs: it drains until the queue is empty and only then waits again.
// Striping puts one consumer per link on the same queue, and there the single
// token is not enough — a burst of pushes collapses into one wakeup, one link
// wakes, and the rest keep sleeping next to a full queue, which is the opposite
// of what striping is for. Re-arming after a successful pop passes the wakeup
// along, so every idle link joins in. It is called with q.mu held; wake() never
// blocks.
func (q *txQueue) wakeIfWork() {
	if q.express.len()+q.bulk.len() > 0 {
		q.wake()
	}
}

func (q *txQueue) dropLocked(p *pbuf) {
	q.stats.dropped.Add(1)
	q.stats.aqmDrop.Add(1)
	q.pool.put(p)
}

// dropStale records an express packet that a fresher one overtook.
func (q *txQueue) dropStale(p *pbuf) {
	q.stats.dropped.Add(1)
	q.stats.staleDrop.Add(1)
	q.pool.put(p)
}

// bulkPop removes the head of the bulk ring and updates the byte accounting.
func (q *txQueue) bulkPop() *pbuf {
	p := q.bulk.pop()
	if p != nil {
		q.bytes -= p.n
	}
	return p
}

// doDequeue is RFC 8289's dodequeue(): pop the head and report whether the
// standing queue has been above target for long enough that it may be dropped.
func (q *txQueue) doDequeue(now int64) (*pbuf, bool) {
	p := q.bulkPop()
	if p == nil {
		q.codel.firstAbove = 0
		return nil, false
	}
	// A queue that holds less than one packet's worth of bytes is not a standing
	// queue, however long this packet waited.
	if now-p.enq < int64(codelTarget) || q.bytes <= q.mtu {
		q.codel.firstAbove = 0
		return p, false
	}
	if q.codel.firstAbove == 0 {
		q.codel.firstAbove = now + int64(codelInterval)
		return p, false
	}
	return p, now >= q.codel.firstAbove
}

// codelDequeue is RFC 8289's deque(): it applies the drop schedule and returns
// the first packet that survives it.
func (q *txQueue) codelDequeue(now int64) *pbuf {
	c := &q.codel
	p, okToDrop := q.doDequeue(now)
	if p == nil {
		c.dropping = false
		return nil
	}

	switch {
	case c.dropping:
		if !okToDrop {
			c.dropping = false
			break
		}
		for now >= c.dropNext && c.dropping {
			q.dropLocked(p)
			c.count++
			p, okToDrop = q.doDequeue(now)
			if p == nil {
				c.dropping = false
				return nil
			}
			if !okToDrop {
				c.dropping = false
			} else {
				c.dropNext = controlLaw(c.dropNext, c.count)
			}
		}
	case okToDrop:
		q.dropLocked(p)
		p, _ = q.doDequeue(now)
		c.dropping = true
		// A burst that resumes soon after the last dropping episode keeps most of
		// the previous count, so the controller does not have to re-converge.
		if delta := c.count - c.lastCount; delta > 1 && now-c.dropNext < 16*int64(codelInterval) {
			c.count = delta
		} else {
			c.count = 1
		}
		c.lastCount = c.count
		c.dropNext = controlLaw(now, c.count)
		if p == nil {
			return nil
		}
	}
	return p
}

// controlLaw schedules the next drop: interval/sqrt(count) after t, so the drop
// rate rises smoothly while the queue stays above target.
func controlLaw(t int64, count uint32) int64 {
	if count == 0 {
		count = 1
	}
	return t + int64(float64(codelInterval)/math.Sqrt(float64(count)))
}

// drain empties the queue, returning every buffer to the pool. Called when a
// link dies so a reconnect does not deliver a burst of packets that are already
// hundreds of milliseconds stale.
func (q *txQueue) drain() {
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		p := q.express.pop()
		if p == nil {
			break
		}
		q.pool.put(p)
	}
	for {
		p := q.bulkPop()
		if p == nil {
			break
		}
		q.pool.put(p)
	}
	q.codel = codel{}
	q.stats.depth.Store(0)
}

// waitCtx blocks until the queue may be non-empty or ctx is done.
func (q *txQueue) waitCtx(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-q.notify:
		return true
	}
}

// ---- classification ---------------------------------------------------------

// isExpress reports whether a packet belongs in the latency-critical class.
//
// The rule is deliberately conservative about reordering. Packets in the two
// classes can overtake each other, and TCP treats reordering within a flow as
// loss, so a packet is only expedited when overtaking is harmless:
//
//   - ICMP/ICMPv6 and UDP have no ordering contract at all.
//   - A TCP segment with no payload (pure ACK, SYN, RST) carries no data that a
//     later segment could arrive before. Expediting ACKs also keeps the inner
//     connection's ACK clock steady, which is what lets it reach full rate.
//   - A TCP FIN is explicitly NOT expedited: it consumes sequence space, and
//     delivering it ahead of queued data would truncate the stream.
func isExpress(p []byte) bool {
	if len(p) < minIPPacket {
		return true // control-sized: nothing to gain by delaying it
	}
	switch p[0] >> 4 {
	case 4:
		ihl := int(p[0]&0x0f) * 4
		if ihl < minIPPacket || ihl > len(p) {
			return len(p) <= smallPacket
		}
		// A non-first fragment has no L4 header to inspect.
		if p[6]&0x1f != 0 || p[7] != 0 {
			return false
		}
		return expressL4(p[9], p[ihl:], len(p))
	case 6:
		const ip6HeaderLen = 40
		if len(p) < ip6HeaderLen {
			return true
		}
		return expressL4(p[6], p[ip6HeaderLen:], len(p))
	}
	return len(p) <= smallPacket
}

// IP protocol numbers used by the classifier.
const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

func expressL4(proto byte, l4 []byte, total int) bool {
	switch proto {
	case protoICMP, protoICMPv6:
		return true
	case protoTCP:
		const tcpMinHeader = 20
		if len(l4) < tcpMinHeader {
			return true
		}
		const (
			flagFIN = 0x01
			flagRST = 0x04
		)
		flags := l4[13]
		if flags&flagRST != 0 {
			return true // tearing a connection down promptly frees both ends
		}
		if flags&flagFIN != 0 {
			return false // consumes sequence space: must stay behind queued data
		}
		doff := int(l4[12]>>4) * 4
		if doff < tcpMinHeader || doff > len(l4) {
			return false
		}
		return len(l4)-doff == 0 // pure ACK or SYN
	case protoUDP:
		return total <= udpExpressMax
	}
	return total <= smallPacket
}
