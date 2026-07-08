package muxeng

import (
	"sync"
	"time"

	"github.com/emergency-tunnel/et/internal/mux"
)

// sessionSet holds the live mux sessions and hands them out round-robin,
// skipping any that have closed. This is where adaptive scaling / quality-based
// selection can plug in later; today it is a fair, lock-light rotation.
type sessionSet struct {
	mu   sync.RWMutex
	list []*mux.Session
	rr   uint64
}

func (s *sessionSet) add(sess *mux.Session) {
	s.mu.Lock()
	s.list = append(s.list, sess)
	s.mu.Unlock()
}

func (s *sessionSet) remove(sess *mux.Session) {
	s.mu.Lock()
	for i, x := range s.list {
		if x == sess {
			s.list = append(s.list[:i], s.list[i+1:]...)
			break
		}
	}
	s.mu.Unlock()
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
		s.rr++
		cand := s.list[int(s.rr)%n]
		if !cand.IsClosed() {
			return cand
		}
	}
	return nil
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
