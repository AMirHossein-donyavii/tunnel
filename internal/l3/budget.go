package l3

import "time"

// A frame is the smallest unit the carrier can interleave: once it has been
// handed to the socket, nothing can overtake it. Its size therefore sets a floor
// on how long a latency-critical packet can be delayed, no matter how good the
// scheduler above it is — a 60 KiB frame takes 24 ms to put on the wire at
// 20 Mbit, and with one frame in flight and one queued that is ~50 ms of
// head-of-line blocking the express class cannot do anything about.
//
// Sizing the frame in bytes cannot satisfy both ends of the range: 60 KiB is
// right on a gigabit link (0.5 ms of wire time, and the syscall and AEAD tag
// amortise nicely) and badly wrong on a 20 Mbit one. So the budget is expressed
// in *time* and converted using the rate the link is actually achieving.
//
// Measured on a shaped 20 Mbit link carrying 2× its capacity in unresponsive
// UDP, with a ping running through the tunnel (min/avg/max in ms, best of three
// runs — the testbed is noisy because which carrier link a flow hashes onto
// matters a lot at this queue depth):
//
//	fixed 60 KiB frames    75.5 / 115.7 / 158.4
//	fixed  8 KiB frames     3.8 /  15.7 /  45.6
//	adaptive                3.3 /  15.5 /  44.5
//
// The adaptive budget reaches the small-frame latency on a slow link without
// imposing its syscall cost on a fast one.
const (
	// targetFrameTime is how long one frame may occupy the link.
	targetFrameTime = 4 * time.Millisecond
	// minFrameBudget keeps a frame large enough to hold a full-size packet plus
	// framing however slow the link is.
	minFrameBudget = 4 * 1024
	// busySample is how much blocked-write time is enough to estimate the drain
	// rate. Small, so the budget reacts within a few frames of congestion
	// starting rather than waiting out a fixed window.
	busySample = 20 * time.Millisecond
	// budgetWindow bounds how long a stale estimate may persist when the link
	// stops blocking.
	budgetWindow = 200 * time.Millisecond
)

// frameBudget derives the frame size that keeps one frame's wire time near
// targetFrameTime.
//
// The rate is measured from how long writes actually *block*, not from
// throughput over wall-clock time. That distinction matters: throughput over
// wall time cannot tell a slow link from an idle one, so it would shrink the
// budget after every quiet period and make the next burst pay for the silence.
// Blocked time only accumulates when the carrier is genuinely the bottleneck —
// which is exactly, and only, when frame size affects latency.
//
// It is used by a single writer goroutine and needs no locking.
type frameBudget struct {
	max     int
	cur     int
	bytes   int
	busy    time.Duration
	since   time.Time
	nowFunc func() time.Time
}

func newFrameBudget(max int) *frameBudget {
	b := &frameBudget{max: max, cur: max, nowFunc: time.Now}
	b.since = b.nowFunc()
	return b
}

// size is the current per-frame byte budget.
func (b *frameBudget) size() int { return b.cur }

// add records a frame of n bytes whose write blocked for the given duration.
func (b *frameBudget) add(n int, blocked time.Duration) {
	b.bytes += n
	b.busy += blocked
	now := b.nowFunc()
	if b.busy < busySample && now.Sub(b.since) < budgetWindow {
		return
	}

	if b.busy >= busySample {
		rate := float64(b.bytes) / b.busy.Seconds() // bytes per second
		want := int(rate * targetFrameTime.Seconds())
		switch {
		case want < minFrameBudget:
			want = minFrameBudget
		case want > b.max:
			want = b.max
		}
		b.cur = want
	} else {
		// The link never made us wait, so it is not the bottleneck and there is
		// nothing to gain from holding frames small.
		b.cur = b.max
	}
	b.bytes, b.busy, b.since = 0, 0, now
}
