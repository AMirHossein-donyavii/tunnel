package l3

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emergency-tunnel/et/internal/logx"
)

// memLink is an in-memory link pair used to drive tunToLink/linkToTun without
// sockets. Frames are copied on write, matching the borrow semantics of the
// real carriers (ReadFrame's result is only valid until the next call).
type memLink struct {
	tx chan []byte
	rx chan []byte

	mu     sync.Mutex
	closed bool
	done   chan struct{}
	cur    []byte
}

func memLinkPair(depth int) (*memLink, *memLink) {
	a2b := make(chan []byte, depth)
	b2a := make(chan []byte, depth)
	a := &memLink{tx: a2b, rx: b2a, done: make(chan struct{})}
	b := &memLink{tx: b2a, rx: a2b, done: make(chan struct{})}
	return a, b
}

var errLinkClosed = errors.New("memlink closed")

func (l *memLink) WriteFrame(p []byte) error {
	cp := append([]byte(nil), p...)
	select {
	case l.tx <- cp:
		return nil
	case <-l.done:
		return errLinkClosed
	}
}

func (l *memLink) ReadFrame() ([]byte, error) {
	select {
	case f := <-l.rx:
		l.cur = f
		return f, nil
	case <-l.done:
		return nil, errLinkClosed
	}
}

func (l *memLink) MaxFrame() int                   { return streamMaxFrame }
func (l *memLink) SetReadDeadline(time.Time) error { return nil }

func (l *memLink) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.closed = true
		close(l.done)
	}
	return nil
}

func testEngine(t *testing.T) *Engine {
	t.Helper()
	e := &Engine{
		log:        logx.New(io.Discard, logx.ERROR),
		pktLen:     1500,
		batchSize:  64,
		hbInterval: 20 * time.Millisecond,
		hbTimeout:  2 * time.Second,
	}
	e.pool = newBufPool(e.pktLen)
	return e
}

// TestPumpDeliversPackets drives the real writer and reader against each other
// and checks every packet arrives intact and in order.
func TestPumpDeliversPackets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sender := testEngine(t)
	receiver := testEngine(t)
	// No heartbeats during this test: it asserts on exactly what is delivered.
	sender.hbInterval = time.Hour
	receiver.hbInterval = time.Hour

	tq := newTxQueue(1024, 1380, sender.pool, &sender.qstats)
	la, lb := memLinkPair(64)
	defer la.Close()
	defer lb.Close()

	out := &fakeQueue{}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); sender.tunToLink(ctx, tq, la, &pumpState{ctlOut: make(chan ctlMsg, 8)}) }()
	go func() {
		defer wg.Done()
		ps := &pumpState{ctlOut: make(chan ctlMsg, 8)}
		receiver.linkToTun(ctx, out, lb, ps)
	}()

	const n = 500
	for i := 0; i < n; i++ {
		p := sender.pool.get()
		p.n = copy(p.b, bulkPacket(300, byte(i)))
		tq.push(p)
	}

	deadline := time.After(5 * time.Second)
	for len(out.snapshot()) < n {
		select {
		case <-deadline:
			t.Fatalf("only %d/%d packets delivered", len(out.snapshot()), n)
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	la.Close()
	lb.Close()
	wg.Wait()

	written := out.snapshot()
	for i := 0; i < n; i++ {
		got := written[i]
		if got[len(got)-1] != byte(i) {
			t.Fatalf("packet %d out of order (marker %d)", i, got[len(got)-1])
		}
	}
	if got := atomic.LoadUint64(&sender.stats.txPackets); got != n {
		t.Errorf("txPackets = %d, want %d", got, n)
	}
	if got := atomic.LoadUint64(&receiver.stats.rxPackets); got != n {
		t.Errorf("rxPackets = %d, want %d", got, n)
	}
}

// TestPumpBatchesUnderLoad checks the opportunistic batching actually batches:
// a burst of packets must not become a frame each.
func TestPumpBatchesUnderLoad(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	e := testEngine(t)
	e.hbInterval = time.Hour
	tq := newTxQueue(4096, 1380, e.pool, &e.qstats)

	// Fill the queue before the writer starts so it has a backlog to batch.
	const n = 512
	for i := 0; i < n; i++ {
		p := e.pool.get()
		p.n = copy(p.b, bulkPacket(300, byte(i)))
		tq.push(p)
	}

	la, lb := memLinkPair(1024)
	defer la.Close()
	defer lb.Close()
	go e.tunToLink(ctx, tq, la, &pumpState{ctlOut: make(chan ctlMsg, 8)})

	frames, packets := 0, 0
	deadline := time.After(5 * time.Second)
	for packets < n {
		select {
		case f := <-lb.rx:
			frames++
			pkts, _, _ := splitFrame(f)
			packets += len(pkts)
		case <-deadline:
			t.Fatalf("only %d/%d packets after %d frames", packets, n, frames)
		}
	}
	// batchSize is 64, so 512 packets need at least 8 frames; anything close to
	// one frame per packet means batching regressed.
	if frames > n/8 {
		t.Errorf("%d packets took %d frames — batching is not coalescing", packets, frames)
	}
}

// TestPumpRTT verifies the control channel: a ping is answered with a pong and
// the round trip is recorded.
func TestPumpRTT(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A: sends pings (short heartbeat) and records the RTT from the pongs.
	a := testEngine(t)
	a.hbInterval = 5 * time.Millisecond
	// B: answers pings.
	b := testEngine(t)
	b.hbInterval = time.Hour

	tqA := newTxQueue(64, 1380, a.pool, &a.qstats)
	tqB := newTxQueue(64, 1380, b.pool, &b.qstats)
	la, lb := memLinkPair(64)
	defer la.Close()
	defer lb.Close()

	psA := &pumpState{ctlOut: make(chan ctlMsg, 8)}
	psB := &pumpState{ctlOut: make(chan ctlMsg, 8)}

	go a.tunToLink(ctx, tqA, la, psA)
	go a.linkToTun(ctx, &fakeQueue{}, la, psA)
	go b.tunToLink(ctx, tqB, lb, psB)
	go b.linkToTun(ctx, &fakeQueue{}, lb, psB)

	deadline := time.After(3 * time.Second)
	for {
		if rtt := a.Snapshot().(Stats).RTTMs; rtt > 0 {
			return // RTT measured end to end
		}
		select {
		case <-deadline:
			t.Fatal("no RTT sample recorded from the control channel")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// A frame that cannot fit even in an empty batch must be shed, not fail the
// link.
func TestOversizedPacketIsShed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	e := testEngine(t)
	e.hbInterval = time.Hour
	e.pktLen = 4096
	e.pool = newBufPool(e.pktLen)
	tq := newTxQueue(64, 1380, e.pool, &e.qstats)

	la, lb := memLinkPair(8)
	defer la.Close()
	defer lb.Close()
	// A link whose frames are smaller than the packet we are about to enqueue.
	small := &smallFrameLink{memLink: la}
	go e.tunToLink(ctx, tq, small, &pumpState{ctlOut: make(chan ctlMsg, 8)})

	p := e.pool.get()
	p.n = copy(p.b, bulkPacket(2000, 1))
	tq.push(p)

	// Follow it with a packet that does fit; it must still get through.
	p2 := e.pool.get()
	p2.n = copy(p2.b, bulkPacket(200, 2))
	tq.push(p2)

	select {
	case f := <-lb.rx:
		pkts, _, _ := splitFrame(f)
		if len(pkts) != 1 || pkts[0][len(pkts[0])-1] != 2 {
			t.Fatalf("expected only the small packet, got %d packets", len(pkts))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("oversized packet wedged the writer")
	}
	if e.qstats.dropped.Load() != 1 {
		t.Errorf("dropped = %d, want 1", e.qstats.dropped.Load())
	}
}

type smallFrameLink struct{ *memLink }

func (l *smallFrameLink) MaxFrame() int { return 1024 }
