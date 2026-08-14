package l3

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
)

// The ring has to be deep enough to hold what a long path keeps in flight, or a
// burst is tail-dropped before CoDel can signal congestion gently. A 100 Mbit
// path at 150 ms — Iran to Europe — carries about 1420 packets at the datagram
// carriers' MTU, which the old 512-packet ring could not hold.
func TestChannelDefaultByProfile(t *testing.T) {
	cases := map[string]int{
		config.ProfileFast:     4096,
		config.ProfileBalance:  2048,
		config.ProfileResource: 256,  // a small VPS caps what a backlog may hold
		"":                     2048, // unknown -> balance
	}
	for profile, want := range cases {
		if got := channelDefault(profile); got != want {
			t.Errorf("channelDefault(%q)=%d, want %d", profile, got, want)
		}
	}

	// The two profiles meant for real servers must cover a long, fast path.
	const inFlight100Mbit150ms = 1420
	for _, p := range []string{config.ProfileFast, config.ProfileBalance} {
		if got := channelDefault(p); got < inFlight100Mbit150ms {
			t.Errorf("profile %q rings at %d packets, below the %d a 100 Mbit path at "+
				"150 ms keeps in flight — bursts will be tail-dropped", p, got, inFlight100Mbit150ms)
		}
	}
}

// fakeQueue implements the queue interface for testing without a real TUN
// device. Writes come from an engine goroutine while the test inspects them, so
// the written log is mutex-guarded.
type fakeQueue struct {
	packets [][]byte
	idx     int

	mu      sync.Mutex
	written [][]byte
}

func (q *fakeQueue) Read(p []byte) (int, error) {
	if q.idx >= len(q.packets) {
		return 0, io.EOF // drained -> queueReader returns (as on device close)
	}
	n := copy(p, q.packets[q.idx])
	q.idx++
	return n, nil
}

func (q *fakeQueue) Write(p []byte) (int, error) {
	q.mu.Lock()
	q.written = append(q.written, append([]byte(nil), p...))
	q.mu.Unlock()
	return len(p), nil
}

// snapshot returns a copy of everything written so far.
func (q *fakeQueue) snapshot() [][]byte {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([][]byte(nil), q.written...)
}

// bulkPacket builds a TCP data packet of the given total length, which the
// classifier must place in the bulk class.
func bulkPacket(total int, marker byte) []byte {
	if total < 40 {
		total = 40
	}
	p := make([]byte, total)
	p[0] = 0x45 // IPv4, IHL 5
	p[2] = byte(total >> 8)
	p[3] = byte(total)
	p[9] = protoTCP
	p[20+12] = 5 << 4 // TCP data offset 5 -> 20 bytes of header, rest is payload
	p[20+13] = 0x10   // ACK
	p[len(p)-1] = marker
	return p
}

// TestQueueReaderFeedsScheduler checks that queueReader hands every packet it
// reads to the scheduler in a pooled buffer, and that the scheduler serves them
// back in order within a class.
func TestQueueReaderFeedsScheduler(t *testing.T) {
	e := &Engine{pktLen: 1500}
	e.pool = newBufPool(e.pktLen)
	tq := newTxQueue(64, 1380, e.pool, &e.qstats)

	q := &fakeQueue{packets: [][]byte{
		bulkPacket(200, 1),
		bulkPacket(200, 2),
		bulkPacket(200, 3),
	}}

	done := make(chan struct{})
	go func() { e.queueReader(context.Background(), q, tq); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("queueReader did not drain and return")
	}

	for want := byte(1); want <= 3; want++ {
		p := tq.pop()
		if p == nil {
			t.Fatalf("queue drained early, expected marker %d", want)
		}
		b := p.bytes()
		if b[len(b)-1] != want {
			t.Fatalf("out of order: got marker %d, want %d", b[len(b)-1], want)
		}
		e.pool.put(p)
	}
	if p := tq.pop(); p != nil {
		t.Fatal("scheduler returned more packets than were read")
	}
}

// TestQueueOverflowTailDrops verifies the hard cap sheds the newest bulk packet
// rather than growing without bound.
func TestQueueOverflowTailDrops(t *testing.T) {
	e := &Engine{pktLen: 1500}
	e.pool = newBufPool(e.pktLen)
	tq := newTxQueue(16, 1380, e.pool, &e.qstats)

	const n = 200
	for i := 0; i < n; i++ {
		p := e.pool.get()
		pkt := bulkPacket(200, byte(i))
		p.n = copy(p.b, pkt)
		tq.push(p)
	}
	if got := e.qstats.dropped.Load(); got == 0 {
		t.Fatal("expected overflow drops once the ring filled")
	}
	queued := 0
	for tq.pop() != nil {
		queued++
	}
	if queued > 16 {
		t.Fatalf("ring held %d packets, capacity is 16", queued)
	}
}
