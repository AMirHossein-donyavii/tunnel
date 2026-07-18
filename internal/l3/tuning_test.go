package l3

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
)

func TestChannelDefaultByProfile(t *testing.T) {
	cases := map[string]int{
		config.ProfileFast:     512,
		config.ProfileBalance:  256,
		config.ProfileResource: 128,
		"":                     256, // unknown -> balance
	}
	for profile, want := range cases {
		if got := channelDefault(profile); got != want {
			t.Errorf("channelDefault(%q)=%d, want %d", profile, got, want)
		}
	}
	// Shallower than the old fixed 1024 (the standing-queue bufferbloat fix).
	if channelDefault(config.ProfileFast) >= 1024 {
		t.Error("fast channel depth should be well below the old 1024")
	}
}

// fakeQueue implements the queue interface for testing queueReader's drop-head
// behaviour without a real TUN device.
type fakeQueue struct {
	packets [][]byte
	idx     int
}

func (q *fakeQueue) Read(p []byte) (int, error) {
	if q.idx >= len(q.packets) {
		return 0, io.EOF // drained -> queueReader returns (as on device close)
	}
	n := copy(p, q.packets[q.idx])
	q.idx++
	return n, nil
}
func (q *fakeQueue) Write(p []byte) (int, error) { return len(p), nil }

// TestQueueReaderDropHead verifies that when the TX channel is full, queueReader
// evicts the OLDEST packet and enqueues the newest, so the consumer always sees
// the freshest data rather than stale buffered packets.
func TestQueueReaderDropHead(t *testing.T) {
	e := &Engine{pktLen: 64}
	e.pool.New = func() any { b := make([]byte, e.pktLen); return &b }

	// Capacity-1 channel; feed three distinct packets with no consumer.
	ch := make(chan []byte, 1)
	q := &fakeQueue{packets: [][]byte{{1}, {2}, {3}}}

	done := make(chan struct{})
	go func() { e.queueReader(context.Background(), q, ch); close(done) }()

	select {
	case <-done: // reader processed all three then hit EOF and returned
	case <-time.After(2 * time.Second):
		t.Fatal("queueReader did not drain and return")
	}

	// The single slot should hold the NEWEST packet (3), not the oldest (1).
	select {
	case pkt := <-ch:
		if len(pkt) != 1 || pkt[0] != 3 {
			t.Fatalf("drop-head should keep the freshest packet {3}, got %v", pkt)
		}
	default:
		t.Fatal("expected a packet in the channel")
	}
}
