package muxeng

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/emergency-tunnel/et/internal/mux"
)

// sessionSet holds the live mux sessions and hands them out round-robin,
// skipping any that have closed. This is where adaptive scaling / quality-based
// selection can plug in later; today it is a fair, lock-light rotation.
type sessionSet struct {
	mu   sync.RWMutex
	list []*mux.Session
	// rr is advanced by pick, which holds only a READ lock so that many
	// concurrent user connections can select a session in parallel. That makes
	// the counter shared mutable state under a shared lock, so it must be
	// atomic — incrementing it directly was a genuine data race on every busy
	// entry-side tunnel.
	rr atomic.Uint64
}

// add registers a session and returns the new live-session count (under the
// lock, so the 0->1 transition can be detected race-free by the caller).
func (s *sessionSet) add(sess *mux.Session) int {
	s.mu.Lock()
	s.list = append(s.list, sess)
	n := len(s.list)
	s.mu.Unlock()
	return n
}

// remove unregisters a session and returns the remaining count (race-free, so
// the 1->0 transition can be detected by the caller).
func (s *sessionSet) remove(sess *mux.Session) int {
	s.mu.Lock()
	for i, x := range s.list {
		if x == sess {
			s.list = append(s.list[:i], s.list[i+1:]...)
			break
		}
	}
	n := len(s.list)
	s.mu.Unlock()
	return n
}

// pick returns the next live session round-robin, or nil if none are available.
func (s *sessionSet) pick() *mux.Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := len(s.list)
	if n == 0 {
		return nil
	}
	for i := 0; i < n; i++ {
		cand := s.list[int(s.rr.Add(1)%uint64(n))]
		if !cand.IsClosed() {
			return cand
		}
	}
	return nil
}

// queued sums the egress backlog across live sessions.
func (s *sessionSet) queued() (cur, peak int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, x := range s.list {
		c, p := x.QueuedBytes()
		cur += c
		if p > peak {
			peak = p
		}
	}
	return cur, peak
}

func (s *sessionSet) count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.list)
}

// bestRTT returns the lowest measured RTT across live sessions.
func (s *sessionSet) bestRTT() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	best := time.Duration(0)
	for _, x := range s.list {
		r := x.LastRTT()
		if r > 0 && (best == 0 || r < best) {
			best = r
		}
	}
	return best
}

func (s *sessionSet) closeAll() {
	s.mu.Lock()
	list := s.list
	s.list = nil
	s.mu.Unlock()
	for _, x := range list {
		x.Close()
	}
}
