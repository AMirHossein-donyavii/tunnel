package l3

import (
	"github.com/emergency-tunnel/et/internal/config"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Striping puts one consumer per carrier link on a single transmit queue, which
// is a change of kind, not degree: the queue was written for one producer and
// one consumer. Two properties have to hold or striping silently corrupts the
// tunnel rather than speeding it up — every packet must come out exactly once,
// and every idle consumer must actually be woken.

// A packet handed to a shared queue must be delivered once. Twice injects a
// duplicate into the peer's TUN device; never loses a packet the sender
// believes it sent.
func TestASharedQueueDeliversEveryPacketExactlyOnce(t *testing.T) {
	const (
		packets   = 20000
		consumers = 4
	)
	pool := newBufPool(2048)
	var stats qstats
	q := newTxQueueAQM(packets*2, 1400, pool, &stats, false)

	seen := make([]int32, packets)
	var delivered atomic.Int64
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < consumers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				p := q.pop()
				if p == nil {
					select {
					case <-stop:
						if q.pop() == nil {
							return
						}
					case <-q.signal():
					case <-time.After(time.Millisecond):
					}
					continue
				}
				// The packet's identity is written into its payload by the
				// producer below.
				b := p.bytes()
				id := int(b[20])<<16 | int(b[21])<<8 | int(b[22])
				atomic.AddInt32(&seen[id], 1)
				delivered.Add(1)
				pool.put(p)
			}
		}()
	}

	for i := 0; i < packets; i++ {
		p := pool.get()
		p.n = 200
		p.b[0] = 0x45 // an IP packet, so it is classified bulk, not express
		p.b[20], p.b[21], p.b[22] = byte(i>>16), byte(i>>8), byte(i)
		q.push(p)
	}
	deadline := time.After(10 * time.Second)
	for delivered.Load() < packets {
		select {
		case <-deadline:
			t.Fatalf("only %d of %d packets were delivered", delivered.Load(), packets)
		case <-time.After(time.Millisecond):
		}
	}
	close(stop)
	wg.Wait()

	for i, n := range seen {
		if n != 1 {
			t.Fatalf("packet %d came out %d times, want exactly 1 — striping must not "+
				"duplicate or drop what the queue accepted", i, n)
		}
	}
}

// push() signals through a channel of capacity one. With a consumer per link on
// one queue that is not enough: a burst of pushes collapses into a single
// wakeup, one link wakes and the others sleep next to a full queue — striping
// that keeps a single link doing all the work, which is the thing it exists to
// avoid. A consumer must pass the wakeup on while packets remain.
func TestEveryIdleConsumerIsWokenByABurst(t *testing.T) {
	const consumers = 4
	pool := newBufPool(2048)
	var stats qstats
	q := newTxQueueAQM(1024, 1400, pool, &stats, false)

	// The burst is queued before any consumer exists, which is what makes this
	// deterministic: however many packets went in, exactly one wakeup token is
	// waiting for them. Whether the other three links ever wake is then entirely
	// a question of whether the first one passes the wakeup on.
	for i := 0; i < 256; i++ {
		p := pool.get()
		p.n = 200
		p.b[0] = 0x45
		q.push(p)
	}

	var woke sync.WaitGroup
	woke.Add(consumers)
	var awake atomic.Int64
	var once sync.Map
	for i := 0; i < consumers; i++ {
		go func(id int) {
			for {
				<-q.signal()
				p := q.pop()
				if p == nil {
					continue
				}
				pool.put(p)
				if _, loaded := once.LoadOrStore(id, true); !loaded {
					awake.Add(1)
					woke.Done()
				}
				// Hold the packet's worth of work briefly so one fast consumer
				// cannot drain the whole burst before the others are scheduled.
				time.Sleep(2 * time.Millisecond)
			}
		}(i)
	}

	done := make(chan struct{})
	go func() { woke.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("only %d of %d consumers were woken by a 256-packet burst — the rest "+
			"stayed asleep beside a queue with work in it, so one link carries "+
			"everything and striping buys nothing", awake.Load(), consumers)
	}
}

// The engine wires striping by pointing every queue slot at one scheduler.
// Getting that backwards is invisible at runtime — the tunnel still works, it
// just quietly goes back to one link per stream — so it is asserted directly.
func TestStripingSharesOneQueueAndFlowPinningDoesNot(t *testing.T) {
	for _, tc := range []struct {
		stripe string
		shared bool
	}{
		{"packet", true},
		{"flow", false},
	} {
		e := testEngine(t)
		e.cfg = &config.Config{MTU: 1380, AQM: config.AQMCodel}
		e.channelSize = 512
		e.stripe = tc.stripe == "packet"
		e.queues = 4
		qs := e.buildTxQueues()
		if len(qs) != 4 {
			t.Fatalf("stripe=%s: built %d queues, want 4", tc.stripe, len(qs))
		}
		allSame := true
		for _, q := range qs[1:] {
			if q != qs[0] {
				allSame = false
			}
		}
		if allSame != tc.shared {
			t.Fatalf("stripe=%s: queues shared = %v, want %v", tc.stripe, allSame, tc.shared)
		}
		// Striping must not multiply how much may be queued: one shared queue
		// of the same total depth, not four of full depth each.
		want := e.channelSize
		if tc.shared {
			want = e.channelSize * 4
		}
		if got := len(qs[0].bulk.buf); got != want {
			t.Fatalf("stripe=%s: bulk depth %d, want %d — striping changes where "+
				"packets may go, not how many may wait", tc.stripe, got, want)
		}
	}
}
