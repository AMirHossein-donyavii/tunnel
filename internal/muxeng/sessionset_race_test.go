package muxeng

import (
	"net"
	"sync"
	"testing"

	"github.com/emergency-tunnel/et/internal/mux"
)

// pick() runs once per user connection, so it is called from many goroutines at
// once. It holds only a read lock, which means anything it mutates must be
// atomic — advancing the round-robin cursor directly was a real data race.
func TestSessionSetPickIsConcurrencySafe(t *testing.T) {
	var set sessionSet
	for i := 0; i < 3; i++ {
		c1, c2 := net.Pipe()
		t.Cleanup(func() { c1.Close(); c2.Close() })
		set.add(mux.Client(c1, mux.Config{AcceptBacklog: 1}))
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				if set.pick() == nil {
					t.Error("pick returned nil with live sessions")
					return
				}
			}
		}()
	}
	wg.Wait()
}

// The rotation must actually rotate: a single session must not be handed out
// for every connection while others idle.
func TestSessionSetPickRotates(t *testing.T) {
	var set sessionSet
	seen := map[*mux.Session]int{}
	for i := 0; i < 3; i++ {
		c1, c2 := net.Pipe()
		t.Cleanup(func() { c1.Close(); c2.Close() })
		set.add(mux.Client(c1, mux.Config{AcceptBacklog: 1}))
	}
	for i := 0; i < 90; i++ {
		seen[set.pick()]++
	}
	if len(seen) != 3 {
		t.Fatalf("rotation used %d of 3 sessions", len(seen))
	}
	for s, n := range seen {
		if n != 30 {
			t.Errorf("session %p got %d of 90 picks, want an even 30", s, n)
		}
	}
}
