package logx

import (
	"strconv"
	"testing"
	"time"
)

func TestFirstIsLoggedAndRepeatsAreCounted(t *testing.T) {
	s := NewSuppressor(5*time.Minute, 64)
	t0 := time.Now()

	if log, n := s.allowAt("1.2.3.4", t0); !log || n != 0 {
		t.Fatalf("the first occurrence must be logged: log=%v suppressed=%d", log, n)
	}
	for i := 1; i <= 59; i++ { // 59*5s = 295s, still inside the 5-minute window
		if log, _ := s.allowAt("1.2.3.4", t0.Add(time.Duration(i)*5*time.Second)); log {
			t.Fatalf("occurrence %d was logged inside the window", i)
		}
	}
	log, n := s.allowAt("1.2.3.4", t0.Add(6*time.Minute))
	if !log {
		t.Fatal("nothing was reported after the window elapsed — the event would vanish entirely")
	}
	if n != 59 {
		t.Fatalf("reported %d suppressed, want 59 — the count is what separates a scanner from a peer in a retry loop", n)
	}
}

// Suppressing by source must not suppress a different source: two servers
// failing for two reasons are two problems.
func TestDistinctSourcesAreIndependent(t *testing.T) {
	s := NewSuppressor(time.Minute, 64)
	t0 := time.Now()
	if log, _ := s.allowAt("a", t0); !log {
		t.Fatal("first source not logged")
	}
	if log, _ := s.allowAt("b", t0); !log {
		t.Fatal("a second source was suppressed by the first one's line")
	}
}

// A scan from thousands of addresses must not turn the log limiter into a leak.
func TestTableStaysBounded(t *testing.T) {
	const max = 128
	s := NewSuppressor(time.Minute, max)
	t0 := time.Now()
	for i := 0; i < 10000; i++ {
		s.allowAt(strconv.Itoa(i), t0)
	}
	s.mu.Lock()
	n := len(s.seen)
	s.mu.Unlock()
	if n > max {
		t.Fatalf("tracking %d sources, past the %d cap", n, max)
	}
}

// Entries that have gone quiet are the ones to drop, so a source still hammering
// the port keeps its suppression rather than being re-logged every eviction.
func TestQuietSourcesAreEvictedBeforeBusyOnes(t *testing.T) {
	s := NewSuppressor(time.Minute, 4)
	t0 := time.Now()
	s.allowAt("quiet", t0)
	s.allowAt("busy", t0.Add(2*time.Minute))

	// Fill up, forcing an eviction at a moment when "quiet" is stale and "busy"
	// is not.
	now := t0.Add(2 * time.Minute)
	s.allowAt("x", now)
	s.allowAt("y", now)
	s.allowAt("z", now)

	s.mu.Lock()
	_, busyKept := s.seen["busy"]
	_, quietKept := s.seen["quiet"]
	s.mu.Unlock()
	if quietKept && !busyKept {
		t.Fatal("evicted the source that is still repeating and kept the one that stopped")
	}
}
