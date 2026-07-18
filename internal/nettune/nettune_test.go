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
		if o.RcvBuf <= 0 {
			t.Errorf("profile %q: RcvBuf=%d, want profile-sized (>0)", p, o.RcvBuf)
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
