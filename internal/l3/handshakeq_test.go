package l3

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// A connection that opens the tunnel port and then says nothing costs a full
// handshake timeout. Run on the accept path, that timeout is charged to every
// real peer queued behind it: measured against the listening side, one silent
// connection delayed the tunnel's first link by 9.6s and three by 29.7s, which
// is a port scanner holding a tunnel down without trying to.
func TestSilentPeerDoesNotDelayARealOne(t *testing.T) {
	q := newHandshakeQueue()
	defer q.close()

	stuck := make(chan struct{})
	defer close(stuck)
	q.submit(func() (link, error) {
		<-stuck // stands in for a handshake running to its timeout
		return nil, errors.New("handshake timeout")
	}, func() {})

	want := &streamLink{}
	q.submit(func() (link, error) { return want, nil }, func() {})

	got := make(chan link, 1)
	go func() {
		lk, err := q.next()
		if err != nil {
			t.Errorf("next: %v", err)
		}
		got <- lk
	}()

	select {
	case lk := <-got:
		if lk != link(want) {
			t.Fatalf("got a different link than the one that finished")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the silent peer's handshake blocked a real peer's link")
	}
}

// The goroutine a connection costs has to be bounded, or the fix for a stall
// becomes a way to exhaust memory instead. Past the ceiling, candidates are
// dropped rather than queued.
func TestHandshakeQueueShedsAFlood(t *testing.T) {
	q := newHandshakeQueue()
	defer q.close()

	stuck := make(chan struct{})
	defer close(stuck)
	var dropped atomic.Int64
	shake := func() (link, error) { <-stuck; return nil, errors.New("timeout") }
	drop := func() { dropped.Add(1) }

	for i := 0; i < maxPendingHandshakes; i++ {
		q.submit(shake, drop)
	}
	if n := dropped.Load(); n != 0 {
		t.Fatalf("dropped %d candidates while still under the ceiling", n)
	}
	for i := 0; i < 10; i++ {
		q.submit(shake, drop)
	}
	if n := dropped.Load(); n != 10 {
		t.Fatalf("dropped %d of 10 candidates past the ceiling", n)
	}
}

// A closed listener must not leave AcceptLink blocked forever.
func TestHandshakeQueueNextUnblocksOnClose(t *testing.T) {
	q := newHandshakeQueue()
	done := make(chan error, 1)
	go func() { _, err := q.next(); done <- err }()
	q.close()
	select {
	case err := <-done:
		if !errors.Is(err, errListenerClosed) {
			t.Fatalf("got %v, want errListenerClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("next() did not return after the listener closed")
	}
}
