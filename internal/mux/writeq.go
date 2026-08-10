package mux

import (
	"sync"
)

// The session's egress queue is where a multiplexed tunnel decides whose bytes
// go first, and it used to be two plain channels: 256 frames of control and
// 1024 frames of data. A DATA frame holds up to 16 KiB, so the data channel
// alone could hold ~16 MB — on a 20 Mbit link that is six seconds of standing
// queue in front of every frame behind it. Worse, a channel is strictly FIFO,
// so one bulk download's frames sat ahead of every other stream's: opening an
// SSH session while a transfer ran meant waiting out the transfer's backlog.
//
// writeQueue replaces both with:
//
//   - A control class (SYN/RST/PING/GOAWAY — all tiny, all latency-critical)
//     that is always drained first, plus per-stream window-update credit that is
//     coalesced and drained before even that. A window update stuck behind bulk
//     data stalls the peer's sender, so this is a throughput mechanism as much
//     as a latency one.
//   - Per-stream DATA queues served round-robin, so N active streams each get
//     ~1/N of the link instead of whoever queued first getting all of it.
//   - A byte budget across all DATA queues. Once it is reached, Stream.Write
//     blocks, which stops the reader draining the user's socket, which applies
//     TCP backpressure to the user. That is the right answer for a reliable
//     stream — unlike the L3 data plane, where packets arrive from the kernel
//     whether we want them or not and dropping (CoDel) is the only option.
//
// The budget is the whole point: it is small enough that the queue cannot hide
// latency, and per-stream flow control (the receive window) still governs how
// much any one stream may have in flight end to end.

// maxQueuedBytes bounds the DATA bytes held across all streams. It only needs
// to cover the writer's own scheduling gap — enough to keep a full frame ready
// whenever the writer wakes — not a bandwidth-delay product, which per-stream
// windows already handle.
const maxQueuedBytes = 256 * 1024

// ctrlBacklog bounds queued control frames. They are ~10-24 bytes each, so even
// a full backlog is a few tens of KB.
const ctrlBacklog = 1024

// frameRing is a growable FIFO of frames.
type frameRing struct {
	buf  []outFrame
	head int
	size int
}

func (r *frameRing) len() int { return r.size }

func (r *frameRing) push(f outFrame) {
	if r.size == len(r.buf) {
		grown := make([]outFrame, max(8, len(r.buf)*2))
		for i := 0; i < r.size; i++ {
			grown[i] = r.buf[(r.head+i)%len(r.buf)]
		}
		r.buf, r.head = grown, 0
	}
	r.buf[(r.head+r.size)%len(r.buf)] = f
	r.size++
}

func (r *frameRing) pop() (outFrame, bool) {
	if r.size == 0 {
		return outFrame{}, false
	}
	f := r.buf[r.head]
	r.buf[r.head] = outFrame{}
	r.head = (r.head + 1) % len(r.buf)
	r.size--
	return f, true
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// rotation is a round-robin ring of stream IDs that currently have data queued.
type rotation struct {
	ids  []uint32
	next int
}

func (r *rotation) add(id uint32) { r.ids = append(r.ids, id) }

func (r *rotation) removeAt(i int) {
	r.ids = append(r.ids[:i], r.ids[i+1:]...)
	if r.next > i {
		r.next--
	}
}

func (r *rotation) remove(id uint32) {
	for i, x := range r.ids {
		if x == id {
			r.removeAt(i)
			return
		}
	}
}

// writeQueue is one session's egress scheduler.
type writeQueue struct {
	mu   sync.Mutex
	ctrl frameRing
	// Window updates are accumulated per stream rather than queued as individual
	// frames. Two reasons: a burst of small reads cannot flood the control class
	// with one frame per read, and — the important one — a window update can
	// never be dropped for lack of queue space. Losing one is not a hiccup, it
	// permanently strands the peer's sender waiting for credit that will never
	// arrive, so the one frame type that must not be lossy is made lossless by
	// construction. Credit is additive, so coalescing is exact.
	winup      map[uint32]uint32
	winupOrder []uint32
	data       map[uint32]*frameRing // per-stream DATA backlog
	// Two rotations: streams opened low-latency (a forward tagged `@ll`, e.g.
	// gaming or SSH) are served before bulk streams, and each group is fair
	// within itself.
	hi    rotation
	norm  rotation
	bytes int // DATA bytes currently queued

	maxBytes int
	closed   bool

	// ready signals the writer that work is available; space signals blocked
	// producers that the byte budget has room again. Both are capacity-1
	// channels used as edge-triggered wakeups.
	ready chan struct{}
	space chan struct{}

	// stats
	queuedBytes int
	maxObserved int
}

func newWriteQueue() *writeQueue {
	return &writeQueue{
		winup:    make(map[uint32]uint32),
		data:     make(map[uint32]*frameRing),
		maxBytes: maxQueuedBytes,
		ready:    make(chan struct{}, 1),
		space:    make(chan struct{}, 1),
	}
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// putCtrl queues a control frame. Control frames never block on the byte
// budget: they are tiny, and delaying an RST or PING costs far more than the
// bytes they occupy. The backlog cap is a last-resort guard against a wedged
// writer; window updates, the one type whose loss is unrecoverable, do not go
// through here (see putWinUp).
func (q *writeQueue) putCtrl(f outFrame) bool {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return false
	}
	if q.ctrl.len() >= ctrlBacklog {
		// Only reachable if the writer has been stalled for a long time, in which
		// case the session is about to be torn down anyway.
		q.mu.Unlock()
		return false
	}
	q.ctrl.push(f)
	q.mu.Unlock()
	signal(q.ready)
	return true
}

// putWinUp accumulates receive-window credit for a stream. It never fails and
// never blocks.
func (q *writeQueue) putWinUp(id uint32, credit uint32) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	if _, pending := q.winup[id]; !pending {
		q.winupOrder = append(q.winupOrder, id)
	}
	q.winup[id] += credit
	q.mu.Unlock()
	signal(q.ready)
}

// takeWinUp emits one accumulated window update. Caller holds mu.
func (q *writeQueue) takeWinUp() (outFrame, bool) {
	for len(q.winupOrder) > 0 {
		id := q.winupOrder[0]
		q.winupOrder = q.winupOrder[1:]
		credit, ok := q.winup[id]
		if !ok || credit == 0 {
			continue
		}
		delete(q.winup, id)
		return outFrame{typ: frameWinUp, id: id, ctl: credit}, true
	}
	return outFrame{}, false
}

// tryPutData queues a DATA frame if the byte budget allows, reporting whether
// it was accepted. The caller waits on the space channel and retries when it is
// not.
func (q *writeQueue) tryPutData(f outFrame, hi bool) (accepted, closed bool) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return false, true
	}
	// Payload-free frames (FIN) cost nothing and are only here to keep their
	// place in the stream's order, so they are never held back — blocking a
	// close behind a full queue would stall teardown for no benefit.
	//
	// Otherwise: admit while under budget, and always admit into an empty queue
	// so a frame larger than the whole budget can never deadlock.
	if len(f.data) > 0 && q.bytes > 0 && q.bytes+len(f.data) > q.maxBytes {
		q.mu.Unlock()
		return false, false
	}
	r := q.data[f.id]
	if r == nil {
		r = &frameRing{}
		q.data[f.id] = r
		if hi {
			q.hi.add(f.id)
		} else {
			q.norm.add(f.id)
		}
	}
	r.push(f)
	q.bytes += len(f.data)
	if q.bytes > q.maxObserved {
		q.maxObserved = q.bytes
	}
	q.queuedBytes = q.bytes
	q.mu.Unlock()
	signal(q.ready)
	return true, false
}

// take returns the next frame to write: control first, then the next stream in
// round-robin order. ok is false when the queue is empty.
func (q *writeQueue) take() (outFrame, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Window updates first: they are what unblocks the peer's sender, so any
	// delay here is throughput lost in the opposite direction.
	if f, ok := q.takeWinUp(); ok {
		return f, true
	}
	if f, ok := q.ctrl.pop(); ok {
		return f, true
	}
	if f, ok := q.takeFrom(&q.hi); ok {
		return f, true
	}
	return q.takeFrom(&q.norm)
}

// takeFrom serves one frame from the next stream in a rotation. Caller holds mu.
func (q *writeQueue) takeFrom(rot *rotation) (outFrame, bool) {
	for len(rot.ids) > 0 {
		if rot.next >= len(rot.ids) {
			rot.next = 0
		}
		id := rot.ids[rot.next]
		r := q.data[id]
		if r == nil || r.len() == 0 {
			// Stream drained or removed: drop it from the rotation.
			rot.removeAt(rot.next)
			delete(q.data, id)
			continue
		}
		f, _ := r.pop()
		q.bytes -= len(f.data)
		q.queuedBytes = q.bytes
		if r.len() == 0 {
			rot.removeAt(rot.next)
			delete(q.data, id)
		} else {
			// Advance so the next call serves a different stream: this is what
			// turns the queue from "first come, first served" into a fair share.
			rot.next++
		}
		signal(q.space)
		return f, true
	}
	return outFrame{}, false
}

// drop discards a stream's queued DATA, releasing its bytes. Called when a
// stream is reset so a dead stream's backlog does not hold the budget hostage.
func (q *writeQueue) drop(id uint32) {
	q.mu.Lock()
	r := q.data[id]
	if r != nil {
		for {
			f, ok := r.pop()
			if !ok {
				break
			}
			q.bytes -= len(f.data)
			if f.pooled {
				putBuf(f.data)
			}
		}
		delete(q.data, id)
		q.hi.remove(id)
		q.norm.remove(id)
		q.queuedBytes = q.bytes
	}
	delete(q.winup, id)
	q.mu.Unlock()
	signal(q.space)
}

// close releases every queued frame's buffer and wakes all waiters.
func (q *writeQueue) close() {
	q.mu.Lock()
	q.closed = true
	for {
		f, ok := q.ctrl.pop()
		if !ok {
			break
		}
		if f.pooled {
			putBuf(f.data)
		}
	}
	for _, r := range q.data {
		for {
			f, ok := r.pop()
			if !ok {
				break
			}
			if f.pooled {
				putBuf(f.data)
			}
		}
	}
	q.data = map[uint32]*frameRing{}
	q.winup, q.winupOrder = map[uint32]uint32{}, nil
	q.hi, q.norm = rotation{}, rotation{}
	q.bytes = 0
	q.mu.Unlock()
	signal(q.ready)
	signal(q.space)
}

// snapshot reports the current and peak queued DATA bytes.
func (q *writeQueue) snapshot() (cur, peak int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.queuedBytes, q.maxObserved
}
