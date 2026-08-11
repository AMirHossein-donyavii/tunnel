package mux

import (
	"net"
	"testing"
	"time"
)

// A fixed receive window caps a single stream at window/RTT regardless of what
// the path can carry: 512 KiB — the small-server profile — over a 100 ms route
// is 42 Mbit/s, which is why one upload stream crawls on a link that measures
// far higher. Downloads hide it by using many streams at once; a single upload
// does not.
//
// These cover the auto-tuning that lets the window follow the path instead.

func windowPair(t *testing.T, cfg Config) (*Session, *Session) {
	t.Helper()
	c1, c2 := net.Pipe()
	a := Client(c1, cfg)
	b := Server(c2, cfg)
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

// A reader that keeps up grows the window; the sender gets the extra credit.
func TestWindowGrowsForAFastReader(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Window = 64 * 1024 // small, so growth is quick to observe
	cli, srv := windowPair(t, cfg)

	st, err := cli.OpenStream(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *Stream, 1)
	go func() {
		if s, err := srv.AcceptStream(); err == nil {
			accepted <- s
		}
	}()
	var peer *Stream
	select {
	case peer = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("stream was never accepted")
	}

	start := peer.windowForTest()
	if start != cfg.Window {
		t.Fatalf("initial window %d, want %d", start, cfg.Window)
	}

	// Push several windows through, reading immediately — the receiver drains
	// as fast as the sender fills, which is what "window-limited" looks like.
	go func() {
		buf := make([]byte, 16*1024)
		for i := 0; i < 64; i++ {
			if _, err := st.Write(buf); err != nil {
				return
			}
		}
	}()
	sink := make([]byte, 32*1024)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := peer.Read(sink); err != nil {
			break
		}
		if peer.windowForTest() > start {
			break
		}
	}

	if got := peer.windowForTest(); got <= start {
		t.Fatalf("window stayed at %d — a fast reader must not be held to the initial window", got)
	} else {
		t.Logf("window grew %d -> %d", start, got)
	}
}

// Growth must stop at the ceiling rather than run away with memory.
func TestWindowStopsAtTheCeiling(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Window = 64 * 1024
	cli, _ := windowPair(t, cfg)

	st, err := cli.OpenStream(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	max := cli.maxWindow()
	if max != cfg.Window*windowGrowthFactor {
		t.Fatalf("ceiling %d, want %d", max, cfg.Window*windowGrowthFactor)
	}

	// Drive growLocked directly past the ceiling.
	st.rmu.Lock()
	for i := 0; i < 20; i++ {
		st.drained = st.win
		st.lastGrow = time.Now()
		st.growLocked()
	}
	got := st.win
	st.rmu.Unlock()

	if got != max {
		t.Fatalf("window reached %d, want the ceiling %d", got, max)
	}
}

// The sum across streams is what this host may have to hold, so it is bounded
// too — otherwise a throughput fix becomes an out-of-memory one.
func TestSessionWindowBudgetIsBounded(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Window = 1024 * 1024
	cli, _ := windowPair(t, cfg)

	if !cli.reserveWindow(maxSessionWindow / 2) {
		t.Fatal("a reservation inside the budget was refused")
	}
	if cli.reserveWindow(maxSessionWindow) {
		t.Fatal("a reservation past the budget was granted")
	}
	cli.releaseWindow(maxSessionWindow / 2)
	if !cli.reserveWindow(maxSessionWindow / 2) {
		t.Fatal("budget was not returned on release")
	}
}

// A closed stream must hand its window back, or a long-lived session runs out
// of budget and auto-tuning quietly stops working on exactly the sessions that
// live long enough to need it.
func TestClosedStreamReturnsItsWindow(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Window = 1024 * 1024
	cli, _ := windowPair(t, cfg)

	before := cli.winTotal.Load()
	st, err := cli.OpenStream(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := cli.winTotal.Load(); got != before+int64(cfg.Window) {
		t.Fatalf("opening a stream accounted %d, want %d", got-before, cfg.Window)
	}
	cli.removeStream(st.id)
	if got := cli.winTotal.Load(); got != before {
		t.Fatalf("budget after close is %d, want %d — the window leaked", got, before)
	}
}

// A slow path must not be mistaken for a small window: draining a window over
// a long stretch means the path is the limit, and growing would only add
// buffering — the bufferbloat this project spends its effort avoiding.
func TestSlowReaderDoesNotGrowTheWindow(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Window = 64 * 1024
	cli, _ := windowPair(t, cfg)
	st, err := cli.OpenStream(nil, false)
	if err != nil {
		t.Fatal(err)
	}

	st.rmu.Lock()
	st.drained = st.win
	st.lastGrow = time.Now().Add(-2 * growPeriod) // a whole window, but slowly
	extra := st.growLocked()
	got := st.win
	st.rmu.Unlock()

	if extra != 0 || got != cfg.Window {
		t.Fatalf("window grew to %d (+%d) for a slow reader", got, extra)
	}
}

// The window a conformant peer may fill must stay under the buffer guard meant
// for one that does not — otherwise obeying flow control gets a session killed.
func TestWindowCeilingStaysUnderTheBufferGuard(t *testing.T) {
	for _, initial := range []int{512 * 1024, 2 * 1024 * 1024, 4 * 1024 * 1024} {
		cfg := DefaultConfig()
		cfg.Window = initial
		cli, _ := windowPair(t, cfg)
		if got := cli.maxWindow(); got > maxRecvBuffer {
			t.Fatalf("initial %d grows to %d, past the %d per-stream buffer guard",
				initial, got, maxRecvBuffer)
		}
	}
	if maxStreamWindow > maxRecvBuffer {
		t.Fatalf("maxStreamWindow %d exceeds maxRecvBuffer %d", maxStreamWindow, maxRecvBuffer)
	}
}
