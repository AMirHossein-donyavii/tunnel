package nettune

import "testing"

// TestLinkOptionsSndBufAutotune asserts the carrier send buffer is left at 0
// (kernel autotuning) by default and only pinned by an explicit override — the
// anti-bufferbloat fix. A pinned SO_SNDBUF is the standing FIFO behind the ~10 s
// tunnelled ping.
func TestLinkOptionsSndBufAutotune(t *testing.T) {
	for _, p := range []string{"fast", "balance", "resource"} {
		o := LinkOptions(p, 0, 0)
		if o.SndBuf != 0 {
			t.Errorf("profile %q: SndBuf=%d, want 0 (kernel autotune)", p, o.SndBuf)
		}
		// RcvBuf was profile-sized here until it was found to cap the receive
		// window: pinning SO_RCVBUF disables autotuning, so the 256 KiB the
		// resource profile pinned became a hard 21 Mbit/s ceiling per link over
		// a 100 ms route. See TestLinkLeavesSocketBuffersToTheKernel.
		if o.RcvBuf != 0 {
			t.Errorf("profile %q: RcvBuf=%d, want 0 (kernel autotune)", p, o.RcvBuf)
		}
		if !o.BBR {
			t.Errorf("profile %q: BBR should stay enabled", p)
		}
	}
	// An explicit override still pins the send buffer.
	if o := LinkOptions("balance", 2<<20, 0); o.SndBuf != 2<<20 {
		t.Errorf("explicit sndOverride not honored: SndBuf=%d, want %d", o.SndBuf, 2<<20)
	}
	// An rcv override is honored.
	if o := LinkOptions("balance", 0, 3<<20); o.RcvBuf != 3<<20 {
		t.Errorf("explicit rcvOverride not honored: RcvBuf=%d, want %d", o.RcvBuf, 3<<20)
	}
}

// A TCP link must leave both socket buffers to the kernel unless the operator
// pinned one.
//
// Pinning SO_RCVBUF switches off receive-window autotuning, and from then on the
// window can never exceed what was pinned: the resource profile's 256 KiB is a
// 21 Mbit/s ceiling over a 100 ms route, applied to whichever direction flows
// into that server. Datagram carriers are different — UDP has no autotuning —
// and keep sizing their sockets from BufSizes.
func TestLinkLeavesSocketBuffersToTheKernel(t *testing.T) {
	for _, profile := range []string{"fast", "balance", "resource"} {
		o := LinkOptions(profile, 0, 0)
		if o.SndBuf != 0 {
			t.Errorf("%s: SndBuf pinned to %d", profile, o.SndBuf)
		}
		if o.RcvBuf != 0 {
			t.Errorf("%s: RcvBuf pinned to %d — that caps the receive window", profile, o.RcvBuf)
		}
	}

	// An explicit override is still honoured.
	o := LinkOptions("balance", 3<<20, 5<<20)
	if o.SndBuf != 3<<20 || o.RcvBuf != 5<<20 {
		t.Fatalf("overrides ignored: snd=%d rcv=%d", o.SndBuf, o.RcvBuf)
	}

	// Datagram carriers still get concrete sizes.
	for _, profile := range []string{"fast", "balance", "resource"} {
		snd, rcv := BufSizes(profile, 0, 0)
		if snd <= 0 || rcv <= 0 {
			t.Errorf("%s: datagram carriers need real sizes, got snd=%d rcv=%d", profile, snd, rcv)
		}
	}
}
