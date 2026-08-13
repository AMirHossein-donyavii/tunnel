package logx

import (
	"sync"
	"time"
)

// Suppressor collapses an event that repeats from the same source.
//
// A tunnel port on a public address is found by scanners within hours, and one
// that keeps retrying writes a rejection line every few seconds — thousands a
// day, all identical, burying the lines that matter. The first occurrence is
// worth seeing; the ten-thousandth is not, and neither is the operator's real
// problem once it is somewhere in between.
//
// So the first is logged, repeats are counted, and one line per window reports
// how many were suppressed. The count matters: a scanner and a peer stuck in a
// reconnect loop look the same in a single line and quite different at "1 in the
// last 5 minutes" versus "312".
type Suppressor struct {
	window time.Duration
	max    int // most distinct keys tracked; a scan from many hosts must not grow this without bound

	mu   sync.Mutex
	seen map[string]*repeat
}

type repeat struct {
	last       time.Time
	suppressed int
}

// NewSuppressor returns a Suppressor that lets one report per key per window.
func NewSuppressor(window time.Duration, max int) *Suppressor {
	return &Suppressor{window: window, max: max, seen: make(map[string]*repeat)}
}

// Allow reports whether this occurrence should be logged, and if so how many
// were suppressed since the last one that was.
func (s *Suppressor) Allow(key string) (log bool, suppressed int) {
	return s.allowAt(key, time.Now())
}

func (s *Suppressor) allowAt(key string, now time.Time) (bool, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.seen[key]
	if !ok {
		// A distributed scan must not be able to grow this map without bound.
		// Dropping entries that have gone quiet costs at most an extra line
		// from a source that has not been heard from in a full window.
		if len(s.seen) >= s.max {
			s.evict(now)
		}
		s.seen[key] = &repeat{last: now}
		return true, 0
	}
	if now.Sub(r.last) < s.window {
		r.suppressed++
		return false, 0
	}
	n := r.suppressed
	r.last, r.suppressed = now, 0
	return true, n
}

// evict drops entries older than a window, and if that frees nothing, the whole
// table — a bounded table that cannot be cleared is a leak with extra steps.
func (s *Suppressor) evict(now time.Time) {
	for k, r := range s.seen {
		if now.Sub(r.last) >= s.window {
			delete(s.seen, k)
		}
	}
	if len(s.seen) >= s.max {
		clear(s.seen)
	}
}
