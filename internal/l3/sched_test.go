package l3

import (
	"testing"
	"time"
)

// ---- packet builders --------------------------------------------------------

func mkIPv4(proto byte, payload []byte) []byte {
	p := make([]byte, 20+len(payload))
	p[0] = 0x45
	total := len(p)
	p[2], p[3] = byte(total>>8), byte(total)
	p[9] = proto
	copy(p[20:], payload)
	return p
}

// tcpSeg builds a TCP segment with the given flags and payload length.
func tcpSeg(flags byte, payloadLen int) []byte {
	l4 := make([]byte, 20+payloadLen)
	l4[12] = 5 << 4 // data offset 5 words = 20 bytes
	l4[13] = flags
	return mkIPv4(protoTCP, l4)
}

func udpDgram(payloadLen int) []byte {
	return mkIPv4(protoUDP, make([]byte, 8+payloadLen))
}

// ---- classifier -------------------------------------------------------------

func TestClassifier(t *testing.T) {
	const (
		flagFIN = 0x01
		flagSYN = 0x02
		flagRST = 0x04
		flagACK = 0x10
	)
	cases := []struct {
		name    string
		pkt     []byte
		express bool
	}{
		{"icmp echo", mkIPv4(protoICMP, make([]byte, 56)), true},
		{"tcp pure ack", tcpSeg(flagACK, 0), true},
		{"tcp syn", tcpSeg(flagSYN, 0), true},
		{"tcp rst", tcpSeg(flagRST, 0), true},
		{"tcp bulk data", tcpSeg(flagACK, 1300), false},
		// A FIN consumes sequence space; expediting it past queued data would
		// truncate the stream, so it must stay in the bulk class.
		{"tcp fin", tcpSeg(flagACK|flagFIN, 0), false},
		{"tcp fin with data", tcpSeg(flagACK|flagFIN, 500), false},
		{"small udp (dns/quic ack)", udpDgram(60), true},
		{"bulk udp", udpDgram(1200), false},
		{"tiny unknown proto", mkIPv4(200, make([]byte, 10)), true},
		{"large unknown proto", mkIPv4(200, make([]byte, 1200)), false},
		{"runt", []byte{0x45, 0x00}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isExpress(c.pkt); got != c.express {
				t.Errorf("isExpress = %v, want %v", got, c.express)
			}
		})
	}
}

// A non-first IPv4 fragment carries no L4 header, so the bytes at the "L4
// offset" must not be interpreted as TCP flags.
func TestClassifierIgnoresFragments(t *testing.T) {
	p := tcpSeg(0x10, 0) // would classify express as a pure ACK
	p[6] = 0x00
	p[7] = 0xb9 // fragment offset != 0
	if isExpress(p) {
		t.Error("a non-first fragment must not be parsed as TCP")
	}
}

func TestClassifierIPv6ICMP(t *testing.T) {
	p := make([]byte, 40+8)
	p[0] = 0x60
	p[6] = protoICMPv6
	if !isExpress(p) {
		t.Error("ICMPv6 should be express")
	}
}

// ---- queue behaviour --------------------------------------------------------

// testQueue builds a queue with a controllable clock.
func testQueue(t *testing.T, depth int) (*txQueue, *bufPool, *int64) {
	t.Helper()
	pool := newBufPool(1500)
	var stats qstats
	q := newTxQueue(depth, 1380, pool, &stats)
	now := int64(0)
	q.now = func() int64 { return now }
	return q, pool, &now
}

func (q *txQueue) pushBytes(pool *bufPool, pkt []byte) {
	p := pool.get()
	p.n = copy(p.b, pkt)
	q.push(p)
}

// TestExpressJumpsTheQueue is the core latency guarantee: a ping enqueued
// behind a wall of bulk traffic is still served first.
func TestExpressJumpsTheQueue(t *testing.T) {
	q, pool, _ := testQueue(t, 256)

	for i := 0; i < 100; i++ {
		q.pushBytes(pool, tcpSeg(0x10, 1300))
	}
	q.pushBytes(pool, mkIPv4(protoICMP, make([]byte, 56)))

	p := q.pop()
	if p == nil {
		t.Fatal("queue empty")
	}
	if !isExpress(p.bytes()) {
		t.Fatal("bulk packet served before the queued express packet")
	}
}

// A latency-critical packet that has been waiting far too long is worthless:
// delivering it late is worse than dropping it.
// A stale express packet is only worth dropping when something fresher is
// waiting behind it. That is the whole justification — "delivering it late is
// worse than sending what came after" — and it is false when the queue is
// empty.
func TestStaleExpressIsDroppedOnlyWhenSomethingFresherWaits(t *testing.T) {
	t.Run("dropped when overtaken", func(t *testing.T) {
		q, pool, now := testQueue(t, 256)

		q.pushBytes(pool, mkIPv4(protoICMP, make([]byte, 56))) // old
		*now = int64(expressStale) + 1
		q.pushBytes(pool, mkIPv4(protoICMP, make([]byte, 20))) // fresh, behind it

		p := q.pop()
		if p == nil {
			t.Fatal("queue empty")
		}
		if len(p.bytes()) != 20+20 {
			t.Fatalf("got the %d-byte packet; the overtaken one should have been dropped",
				len(p.bytes()))
		}
		if q.stats.dropped.Load() != 1 {
			t.Errorf("dropped = %d, want 1", q.stats.dropped.Load())
		}
	})

	t.Run("delivered when it is all there is", func(t *testing.T) {
		q, pool, now := testQueue(t, 256)

		q.pushBytes(pool, mkIPv4(protoICMP, make([]byte, 56)))
		q.pushBytes(pool, tcpSeg(0x10, 1300))
		*now = int64(expressStale) + 1

		p := q.pop()
		if p == nil {
			t.Fatal("queue empty")
		}
		if !isExpress(p.bytes()) {
			t.Fatal("the only express packet was dropped for being late, with nothing " +
				"fresher to send instead — that turns a carrier hiccup into a ping timeout")
		}
		if q.stats.dropped.Load() != 0 {
			t.Errorf("dropped = %d, want 0", q.stats.dropped.Load())
		}
	})
}

// CoDel must leave a queue alone while its sojourn time is under target — no
// drops on a fast-draining tunnel, however much traffic passes through.
func TestCodelDoesNotDropBelowTarget(t *testing.T) {
	q, pool, now := testQueue(t, 256)

	for i := 0; i < 200; i++ {
		q.pushBytes(pool, tcpSeg(0x10, 1300))
		*now += int64(time.Millisecond) // 1 ms sojourn, well under the 5 ms target
		if p := q.pop(); p != nil {
			pool.put(p)
		}
	}
	if got := q.stats.dropped.Load(); got != 0 {
		t.Errorf("CoDel dropped %d packets on an uncongested queue", got)
	}
}

// With a persistently over-target queue, CoDel must start dropping — that is
// the congestion signal that stops the standing queue from growing.
func TestCodelDropsWhenStandingQueuePersists(t *testing.T) {
	q, pool, now := testQueue(t, 4096)

	// Build a deep backlog, then let time pass so every packet is far over target.
	for i := 0; i < 500; i++ {
		q.pushBytes(pool, tcpSeg(0x10, 1300))
	}
	*now += int64(codelTarget) * 4

	// Drain slowly. The first interval only arms the controller; drops follow.
	for i := 0; i < 500 && q.bulk.len() > 0; i++ {
		*now += int64(10 * time.Millisecond)
		if p := q.pop(); p != nil {
			pool.put(p)
		}
	}
	if q.stats.dropped.Load() == 0 {
		t.Fatal("CoDel never dropped despite a persistent standing queue")
	}
}

// The controller must disarm as soon as the queue recovers.
func TestCodelRecovers(t *testing.T) {
	q, pool, now := testQueue(t, 4096)
	for i := 0; i < 200; i++ {
		q.pushBytes(pool, tcpSeg(0x10, 1300))
	}
	*now += int64(codelTarget) * 4
	for i := 0; i < 50; i++ {
		*now += int64(10 * time.Millisecond)
		if p := q.pop(); p != nil {
			pool.put(p)
		}
	}
	// Drain everything, then run a well-behaved queue and confirm no new drops.
	for {
		p := q.pop()
		if p == nil {
			break
		}
		pool.put(p)
	}
	before := q.stats.dropped.Load()
	for i := 0; i < 100; i++ {
		q.pushBytes(pool, tcpSeg(0x10, 1300))
		*now += int64(time.Millisecond)
		if p := q.pop(); p != nil {
			pool.put(p)
		}
	}
	if got := q.stats.dropped.Load(); got != before {
		t.Errorf("CoDel kept dropping after recovery: %d new drops", got-before)
	}
}

func TestDrainReturnsEverything(t *testing.T) {
	q, pool, _ := testQueue(t, 256)
	for i := 0; i < 50; i++ {
		q.pushBytes(pool, tcpSeg(0x10, 1300))
		q.pushBytes(pool, mkIPv4(protoICMP, make([]byte, 56)))
	}
	q.drain()
	if p := q.pop(); p != nil {
		t.Fatal("drain left packets behind")
	}
	if q.bytes != 0 {
		t.Errorf("byte accounting leaked: %d", q.bytes)
	}
}

// Byte accounting must stay exact across pushes, pops and drops, or the hard
// cap silently stops working.
func TestByteAccounting(t *testing.T) {
	q, pool, _ := testQueue(t, 64)
	pkt := tcpSeg(0x10, 1000)
	for i := 0; i < 10; i++ {
		q.pushBytes(pool, pkt)
	}
	if want := 10 * len(pkt); q.bytes != want {
		t.Fatalf("bytes = %d, want %d", q.bytes, want)
	}
	for i := 0; i < 10; i++ {
		if p := q.pop(); p != nil {
			pool.put(p)
		}
	}
	if q.bytes != 0 {
		t.Fatalf("bytes = %d after full drain, want 0", q.bytes)
	}
}

func TestRingWrapAround(t *testing.T) {
	r := newRing(4)
	pool := newBufPool(64)
	for round := 0; round < 5; round++ {
		for i := 0; i < 4; i++ {
			p := pool.get()
			p.n = 1
			p.b[0] = byte(i)
			if !r.push(p) {
				t.Fatalf("round %d: push %d rejected on an empty ring", round, i)
			}
		}
		if r.push(pool.get()) {
			t.Fatal("push succeeded on a full ring")
		}
		for i := 0; i < 4; i++ {
			p := r.pop()
			if p == nil || p.b[0] != byte(i) {
				t.Fatalf("round %d: got %v, want %d", round, p, i)
			}
		}
		if r.pop() != nil {
			t.Fatal("pop returned a packet from an empty ring")
		}
	}
}

// ---- benchmarks -------------------------------------------------------------

func BenchmarkQueuePushPop(b *testing.B) {
	pool := newBufPool(1500)
	var stats qstats
	q := newTxQueue(1024, 1380, pool, &stats)
	pkt := tcpSeg(0x10, 1300)

	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := pool.get()
		p.n = copy(p.b, pkt)
		q.push(p)
		if got := q.pop(); got != nil {
			pool.put(got)
		}
	}
}

func BenchmarkClassify(b *testing.B) {
	pkt := tcpSeg(0x10, 1300)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = isExpress(pkt)
	}
}

// The transmit ring is a burst absorber, and it was too small to be one: 512
// packets is about 676 KB, while a 100 Mbit path at 150 ms — Iran to Europe —
// has one to two megabytes in flight. A burst arriving faster than CoDel's
// interval overflowed and was tail-dropped, which is the crude drop CoDel exists
// to replace.
//
// A deeper ring is only safe with an AQM in front of it. These two assert both
// halves of that: the capacity absorbs the burst, and the standing queue stays
// short anyway.
func TestDeepRingAbsorbsABurstWithoutTailDropping(t *testing.T) {
	const burst = 1500 // packets, well past the old 512-packet ring
	q, pool, _ := testQueue(t, channelDefault("fast"))

	for i := 0; i < burst; i++ {
		q.pushBytes(pool, tcpSeg(0x10, 1300))
	}
	if got := q.stats.dropped.Load(); got != 0 {
		t.Fatalf("%d of %d packets were tail-dropped on arrival — the ring is still "+
			"too small to absorb a burst this size", got, burst)
	}
	if got := q.bulk.len(); got != burst {
		t.Fatalf("the ring holds %d of %d packets", got, burst)
	}
}

// Capacity must not become standing delay. A drainer that keeps up leaves the
// queue shallow no matter how deep the ring is allowed to get.
func TestADeepRingDoesNotBecomeStandingDelay(t *testing.T) {
	q, pool, now := testQueue(t, channelDefault("fast"))

	// A steady arrival that the drainer keeps up with: one in, one out.
	maxSeen := 0
	for i := 0; i < 5000; i++ {
		*now += int64(100 * time.Microsecond)
		q.pushBytes(pool, tcpSeg(0x10, 1300))
		if p := q.pop(); p != nil {
			pool.put(p)
		}
		if n := q.bulk.len(); n > maxSeen {
			maxSeen = n
		}
	}
	if maxSeen > 4 {
		t.Fatalf("the standing queue reached %d packets while the drainer was keeping "+
			"up — capacity is being used as buffer instead of as headroom", maxSeen)
	}
}

// And with a drainer that cannot keep up, CoDel still drops rather than letting
// the deep ring fill with stale packets.
func TestCodelStillBoundsSojournOnADeepRing(t *testing.T) {
	q, pool, now := testQueue(t, channelDefault("fast"))

	for i := 0; i < 2000; i++ {
		q.pushBytes(pool, tcpSeg(0x10, 1300))
	}
	*now += int64(codelTarget) * 4
	for i := 0; i < 2000 && q.bulk.len() > 0; i++ {
		*now += int64(10 * time.Millisecond)
		if p := q.pop(); p != nil {
			pool.put(p)
		}
	}
	if q.stats.dropped.Load() == 0 {
		t.Fatal("a deep ring let a persistent standing queue build with no drops — " +
			"that is the bufferbloat this capacity is only safe without")
	}
}

// CoDel's control law ramps: the first drop comes an interval after the queue
// goes over target, and the rate climbs as the square root of the count. While
// it converges the queue can be far deeper than target, and how deep depends on
// how much room the ring gives it — so raising the ring to absorb a long path's
// burst also raised the worst case. A 4096-packet ring is five megabytes, which
// at 120 Mbit is a third of a second of standing delay.
//
// The ceiling bounds that in time, which is the same promise at every rate.
func TestNoBulkPacketIsDeliveredPastTheDelayCeiling(t *testing.T) {
	q, pool, now := testQueue(t, channelDefault("fast"))

	// Fill the ring, then let far more than the ceiling elapse without draining.
	for i := 0; i < 2000; i++ {
		q.pushBytes(pool, tcpSeg(0x10, 1300))
	}
	*now += int64(maxQueueDelay) * 3

	// Everything now in the queue is stale. Draining must not hand any of it on.
	for i := 0; i < 3000; i++ {
		p := q.pop()
		if p == nil {
			break
		}
		if age := *now - p.enq; age > int64(maxQueueDelay) {
			t.Fatalf("a packet %v old was delivered; the ceiling is %v",
				time.Duration(age), maxQueueDelay)
		}
		pool.put(p)
	}
	if q.stats.dropped.Load() == 0 {
		t.Fatal("nothing was dropped, so the stale packets were delivered late instead")
	}
}

// The ceiling must not touch a queue that is draining normally: it is a backstop
// for CoDel's ramp, not a second dropper competing with it.
func TestTheDelayCeilingDoesNotDropAHealthyQueue(t *testing.T) {
	q, pool, now := testQueue(t, channelDefault("fast"))

	for i := 0; i < 3000; i++ {
		*now += int64(50 * time.Microsecond)
		q.pushBytes(pool, tcpSeg(0x10, 1300))
		if p := q.pop(); p != nil {
			pool.put(p)
		}
	}
	if got := q.stats.dropped.Load(); got != 0 {
		t.Fatalf("%d packets were dropped from a queue that was keeping up", got)
	}
}

// And express traffic is not subject to it: express has its own, longer bound
// and its own rule about being overtaken (see expressStale).
func TestTheDelayCeilingIsBulkOnly(t *testing.T) {
	q, pool, now := testQueue(t, channelDefault("fast"))
	q.pushBytes(pool, mkIPv4(protoICMP, make([]byte, 56)))
	*now += int64(maxQueueDelay) * 2

	p := q.pop()
	if p == nil {
		t.Fatal("the express packet was dropped by the bulk ceiling")
	}
	if !isExpress(p.bytes()) {
		t.Fatal("got a bulk packet")
	}
	pool.put(p)
}
