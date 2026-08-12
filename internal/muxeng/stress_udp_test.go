package muxeng

import (
	"sync"
	"testing"
	"time"
)

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// The full session lifecycle under contention: many producers offering, a pump
// draining, and teardown arriving from a third goroutine — which is what a busy
// tunnel does when a stream errors or the carrier reconnects mid-burst.
func TestSessionLifecycleUnderContention(t *testing.T) {
	for round := 0; round < 50; round++ {
		s := &udpSession{out: make(chan dgram, udpQueueDepth), closed: make(chan struct{})}
		var wg sync.WaitGroup

		wg.Add(1)
		go func() { defer wg.Done(); pumpTo(s, nopWriter{}) }()

		for i := 0; i < 8; i++ { // many producers, as a busy socket loop bursts
			wg.Add(1)
			go func() {
				defer wg.Done()
				p := make([]byte, 1200)
				for j := 0; j < 300; j++ {
					s.offer(p)
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(round%3) * time.Millisecond)
			s.shutdown()
		}()
		wg.Add(1)
		go func() { defer wg.Done(); s.shutdown() }() // a second closer, as reaper+pump both can

		wg.Wait()
	}
}

// pumpTo mirrors udpSession.pump against an arbitrary writer, so the lifecycle
// can be exercised without a real mux stream.
func pumpTo(s *udpSession, w nopWriter) {
	scratch := make([]byte, 0, 2048)
	for {
		var d dgram
		select {
		case <-s.closed:
			return
		case d = <-s.out:
		}
		if time.Since(d.enq) > udpStale {
			s.dropped.Add(1)
			giveDgram(d.b)
			continue
		}
		_ = writeDatagram(w, &scratch, d.b)
		giveDgram(d.b)
	}
}
