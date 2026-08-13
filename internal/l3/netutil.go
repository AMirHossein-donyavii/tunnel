package l3

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"time"
)

// isTransientReadErr reports whether a socket read error is transient — the read
// should be retried rather than treated as a permanent failure. This matters
// most for the datagram *listeners*, which serve every queue from ONE shared
// socket: killing that socket on a recoverable error (ENOBUFS when the receive
// buffer briefly overflows under load, EINTR, EAGAIN) would strand every link
// until a manual restart. Genuine closure (net.ErrClosed on Close) is not
// transient, so shutdown still stops the loop promptly.
// isTransientWriteErr reports whether a send failed for a reason that says
// nothing about the link.
//
// A raw ICMP socket meets these routinely: ENOBUFS when the interface queue is
// momentarily full, EPERM when a firewall rate-limiter refuses this packet,
// EMSGSIZE for one frame the path will not take. Treating any of them as the
// link being dead cycled the carrier — every packet in flight lost, a re-dial,
// and a visible stall — for something that costs at most one frame.
func isTransientWriteErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	return errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.EINTR) ||
		errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.ENOMEM) ||
		errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EMSGSIZE) ||
		errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.ENETDOWN)
}

func isTransientReadErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	// Only genuine "retry" errors are transient. A deadline Timeout is NOT — the
	// pump sets a read deadline to intentionally unblock a stalled reader, and
	// that must propagate so the link cycles instead of spinning forever.
	return errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.EINTR) ||
		errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.ENOMEM)
}

// isClosed reports whether a done-channel has been closed (non-blocking).
func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// deadlineGate implements net.Conn-style read deadlines for the channel-backed
// datagram flows. Crucially, changing the deadline (e.g. the pump setting it to
// "now" to unblock a stalled reader on link teardown) interrupts a read that is
// ALREADY blocked — the flows' hand-rolled version captured the deadline once at
// entry and so could hang forever, which is exactly the stuck-reader path behind
// the long-run listener wedge.
type deadlineGate struct {
	mu     sync.Mutex
	dl     time.Time
	notify chan struct{}
}

// set updates the read deadline and wakes any in-progress read so it re-reads it.
func (g *deadlineGate) set(t time.Time) {
	g.mu.Lock()
	g.dl = t
	if g.notify != nil {
		close(g.notify)
		g.notify = nil
	}
	g.mu.Unlock()
}

// snapshot returns the current deadline and a channel closed when it next
// changes. The reader selects on that channel and re-evaluates on a change.
func (g *deadlineGate) snapshot() (time.Time, <-chan struct{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.notify == nil {
		g.notify = make(chan struct{})
	}
	return g.dl, g.notify
}

// flowDepth is the per-flow inbound queue depth in the packet-carrier
// demultiplexers. It only has to cover the gap between the shared socket's read
// loop and the flow's reader; a deeper queue would just add delay, since a
// datagram carrier's backlog is not retransmitted.
const flowDepth = 256

// dgramBufSize is the pooled buffer size for the packet-carrier demultiplexers.
// Every carrier datagram fits comfortably inside it (dgramMaxFrame plus AEAD
// and header overhead), so the pool covers the whole hot path.
const dgramBufSize = 2048

// dgramPool recycles the buffers the UDP/ICMP/SPF demultiplexers use to hand a
// datagram from the shared listening socket to its flow. Without it every
// inbound datagram costs one heap allocation, which at a few tens of thousands
// of packets per second is the single largest source of GC pressure on the
// packet carriers.
var dgramPool = sync.Pool{New: func() any { b := make([]byte, dgramBufSize); return &b }}

// getDgram returns a pooled buffer holding a copy of src.
func getDgram(src []byte) *[]byte {
	if len(src) > dgramBufSize {
		b := make([]byte, len(src))
		copy(b, src)
		return &b
	}
	bp := dgramPool.Get().(*[]byte)
	b := (*bp)[:cap(*bp)][:len(src)]
	copy(b, src)
	*bp = b
	return bp
}

// putDgram returns a buffer to the pool. Buffers that did not come from it (an
// oversized datagram) are simply dropped for the GC.
func putDgram(bp *[]byte) {
	if bp == nil || cap(*bp) != dgramBufSize {
		return
	}
	*bp = (*bp)[:dgramBufSize]
	dgramPool.Put(bp)
}

// wait blocks until data arrives on in, the flow closes, or the deadline passes.
// It honours deadline changes made mid-wait. Returns the payload, or a nil slice
// with an error (timeoutErr on deadline, net.ErrClosed on close).
//
// The caller owns the returned buffer and must hand it back with putDgram.
func (g *deadlineGate) wait(in <-chan *[]byte, closed <-chan struct{}) (*[]byte, error) {
	for {
		dl, changed := g.snapshot()
		var timeout <-chan time.Time
		var timer *time.Timer
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return nil, timeoutErr{}
			}
			timer = time.NewTimer(d)
			timeout = timer.C
		}
		select {
		case pkt := <-in:
			if timer != nil {
				timer.Stop()
			}
			return pkt, nil
		case <-timeout:
			return nil, timeoutErr{}
		case <-closed:
			if timer != nil {
				timer.Stop()
			}
			return nil, net.ErrClosed
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
			// deadline changed mid-wait; re-evaluate with the new value
		}
	}
}
