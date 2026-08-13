package l3

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// flakyQueue fails a configurable number of writes, then succeeds.
type flakyQueue struct {
	mu       sync.Mutex
	failures int
	err      error
	written  int
}

func (q *flakyQueue) Read(p []byte) (int, error) { select {} }

func (q *flakyQueue) Write(p []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.failures > 0 {
		q.failures--
		return 0, q.err
	}
	q.written++
	return len(p), nil
}

func (q *flakyQueue) count() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.written
}

// A write to the TUN device can fail for reasons that have nothing to do with
// the carrier: the kernel's queue is momentarily full (ENOBUFS), or the peer
// sent one packet the device will not accept (EINVAL). The reader treated any
// such error as the link being dead and returned, which tears the carrier down
// and re-dials it — hundreds of milliseconds during which everything is lost.
//
// On the ICMP carrier that is exactly what a ping through the VPN shows as an
// occasional timeout: one unlucky packet, and the whole tunnel cycles.
//
// A packet the device rejects is one packet. Drop it and keep the link.
func TestATunWriteErrorDropsThePacketNotTheLink(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	e := testEngine(t)
	la, lb := memLinkPair(64)
	defer la.Close()
	defer lb.Close()

	q := &flakyQueue{failures: 3, err: errors.New("write /dev/net/tun: no buffer space available")}

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.linkToTun(ctx, q, lb, &pumpState{ctlOut: make(chan ctlMsg, 8)})
	}()

	// Ten packets: the first three are rejected by the device, the rest must
	// still arrive.
	pkt := make([]byte, 60)
	pkt[0] = 0x45
	for i := 0; i < 10; i++ {
		frame := appendPacket(nil, pkt)
		if err := la.WriteFrame(frame); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	deadline := time.After(3 * time.Second)
	for q.count() < 7 {
		select {
		case <-done:
			t.Fatalf("the reader gave up after a device write error — the carrier is torn "+
				"down and re-dialed for one packet the device would not take (%d delivered)",
				q.count())
		case <-deadline:
			t.Fatalf("only %d of 7 packets were delivered", q.count())
		case <-time.After(time.Millisecond):
		}
	}

	// And the failures must be visible, or a device dropping packets looks
	// exactly like the path dropping them.
	if got := atomic.LoadUint64(&e.stats.tunWriteErrs); got != 3 {
		t.Fatalf("recorded %d device write errors, want 3 — invisible drops cannot be diagnosed", got)
	}
}

// A device that fails every write forever is not a transient condition, and
// carrying on would spin. The link must give up so the pump re-dials.
func TestAPermanentlyFailingDeviceStillEndsTheLink(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	e := testEngine(t)
	la, lb := memLinkPair(1024)
	defer la.Close()
	defer lb.Close()

	q := &flakyQueue{failures: 1 << 30, err: errors.New("write /dev/net/tun: file already closed")}

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.linkToTun(ctx, q, lb, &pumpState{ctlOut: make(chan ctlMsg, 8)})
	}()

	pkt := make([]byte, 60)
	pkt[0] = 0x45
	go func() {
		for i := 0; i < maxTunWriteErrs*4; i++ {
			if err := la.WriteFrame(appendPacket(nil, pkt)); err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the reader never gave up on a device that fails every write")
	}
}
