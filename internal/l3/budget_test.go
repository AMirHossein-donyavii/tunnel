package l3

import (
	"testing"
	"time"
)

// linkSim drives a frameBudget against a simulated carrier. `rate` is the
// link's drain rate; `sock` is how many bytes the kernel accepts without
// blocking, so a write only stalls once the socket is full — the same shape as
// a real congested socket.
type linkSim struct {
	b        *frameBudget
	now      time.Time
	rate     float64 // bytes per second the link drains
	sock     int     // socket buffer capacity in bytes
	inFlight float64 // bytes currently sitting in the socket buffer
}

func newLinkSim(max int, bytesPerSecond float64, sockBytes int) *linkSim {
	s := &linkSim{now: time.Unix(0, 0), rate: bytesPerSecond, sock: sockBytes}
	s.b = newFrameBudget(max)
	s.b.nowFunc = func() time.Time { return s.now }
	s.b.since = s.now
	return s
}

// write pushes one full-budget frame, returning how long it blocked.
func (s *linkSim) write() (int, time.Duration) {
	sz := s.b.size()
	// The socket drains at `rate` while we are not writing; assume the previous
	// gap was negligible, so blocking is whatever does not fit right now.
	over := s.inFlight + float64(sz) - float64(s.sock)
	var blocked time.Duration
	if over > 0 {
		blocked = time.Duration(over / s.rate * float64(time.Second))
		s.inFlight = float64(s.sock)
	} else {
		s.inFlight += float64(sz)
	}
	s.now = s.now.Add(blocked)
	return sz, blocked
}

func (s *linkSim) sendFrames(n int) {
	for i := 0; i < n; i++ {
		s.b.add(s.write())
	}
}

// wireTime is how long one full frame occupies the simulated link.
func (s *linkSim) wireTime() time.Duration {
	return time.Duration(float64(s.b.size()) / s.rate * float64(time.Second))
}

// On a congested slow link the budget must shrink until a frame no longer
// monopolises the wire — this is what lets the express class pre-empt bulk
// traffic at all.
func TestFrameBudgetTracksSlowLink(t *testing.T) {
	const twentyMbit = 20e6 / 8
	s := newLinkSim(60*1024, twentyMbit, 64*1024)
	s.sendFrames(500)

	if got := s.wireTime(); got > 2*targetFrameTime {
		t.Errorf("one frame occupies a 20 Mbit link for %s (%d bytes); target is %s",
			got, s.b.size(), targetFrameTime)
	}
	if s.b.size() < minFrameBudget {
		t.Errorf("budget %d fell below the floor %d", s.b.size(), minFrameBudget)
	}
}

// A link that never blocks is not the bottleneck: the budget must stay at the
// carrier maximum so syscall and AEAD cost stay amortised.
func TestFrameBudgetUsesFullFramesWhenNeverBlocked(t *testing.T) {
	s := newLinkSim(60*1024, 1e9/8, 16<<20) // gigabit, huge socket buffer
	s.sendFrames(500)
	if got := s.b.size(); got != 60*1024 {
		t.Errorf("budget on an unblocked link = %d, want the full %d", got, 60*1024)
	}
}

// The budget must adapt in both directions as the carrier's capacity changes.
func TestFrameBudgetAdaptsBothWays(t *testing.T) {
	s := newLinkSim(60*1024, 20e6/8, 64*1024)
	s.sendFrames(500)
	slow := s.b.size()
	if slow >= 60*1024 {
		t.Fatalf("budget did not shrink on a congested slow link: %d", slow)
	}

	// The link speeds up: writes stop blocking and the budget must recover.
	s.rate = 1e9 / 8
	s.sock = 16 << 20
	s.inFlight = 0
	for i := 0; i < 100; i++ {
		n, blocked := s.write()
		s.now = s.now.Add(budgetWindow / 10) // wall clock still advances
		s.b.add(n, blocked)
	}
	if s.b.size() <= slow {
		t.Fatalf("budget did not recover when the link sped up: %d -> %d", slow, s.b.size())
	}
}

// Idle time must not shrink the budget: silence is not evidence of a slow link,
// and making the next burst pay for the previous quiet period is exactly the
// bug a wall-clock throughput estimator would have.
func TestFrameBudgetIgnoresIdleTime(t *testing.T) {
	s := newLinkSim(60*1024, 20e6/8, 64*1024)
	s.sendFrames(500)
	congested := s.b.size()

	// Now go quiet for a long time with a trickle of instantly-accepted frames.
	s.sock = 16 << 20
	s.inFlight = 0
	for i := 0; i < 20; i++ {
		s.now = s.now.Add(time.Second)
		s.b.add(100, 0)
	}
	if s.b.size() != s.b.max {
		t.Errorf("after going idle the budget is %d, want the max %d (was %d while congested)",
			s.b.size(), s.b.max, congested)
	}
}

// However slow the link, a frame must still hold a full-size packet.
func TestFrameBudgetNeverBelowFloor(t *testing.T) {
	s := newLinkSim(60*1024, 2000, 4096) // 16 kbit/s
	s.sendFrames(200)
	if got := s.b.size(); got != minFrameBudget {
		t.Errorf("budget on a crawling link = %d, want the floor %d", got, minFrameBudget)
	}
}
