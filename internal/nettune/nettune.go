// Package nettune applies transport-level performance tuning to tunnel links:
// socket buffer sizes, TCP_NODELAY, TCP_QUICKACK, TCP_USER_TIMEOUT, keepalive,
// and (on Linux) the BBR congestion control algorithm. Buffer sizing follows
// the performance profile unless overridden.
package nettune

import "time"

// Options is the full set of link tunables. Zero values mean "leave default".
type Options struct {
	SndBuf      int           // SO_SNDBUF bytes
	RcvBuf      int           // SO_RCVBUF bytes
	UserTimeout time.Duration // TCP_USER_TIMEOUT: drop link if unacked this long
	Keepalive   time.Duration // TCP keepalive idle/interval
	BBR         bool          // request BBR congestion control
	// NotSentLowat bounds the bytes the kernel will hold in the socket send
	// queue that have not yet been put on the wire (TCP_NOTSENT_LOWAT).
	NotSentLowat int
}

// notSentLowat is the ceiling on un-transmitted bytes sitting in the kernel's
// send queue.
//
// This is the other half of the anti-bufferbloat story. Leaving SO_SNDBUF to
// kernel autotuning (see LinkOptions) stops us from *pinning* a huge buffer,
// but autotuning still grows the send queue to a full bandwidth-delay product,
// and on a congested path the kernel will happily accept that much application
// data and dribble it out. Anything already handed to the kernel is beyond the
// reach of the tunnel's own priority scheduler, so an interactive packet
// classified as express still ends up behind however many megabytes of bulk
// data the kernel accepted a moment earlier.
//
// TCP_NOTSENT_LOWAT keeps the socket unwritable until the unsent backlog falls
// below this mark, so the queue lives in the tunnel's scheduler — where CoDel
// can measure its delay and the express class can jump it — instead of in the
// kernel where nothing can. 128 KiB is comfortably more than is needed to keep
// the NIC busy at any rate this tunnel runs at, so throughput is unaffected.
const notSentLowat = 128 << 10

// LinkOptions builds recommended options for a TUNNEL LINK (the TCP carrier
// used by the mux engine and the L3 tcp carrier). Datagram carriers size their
// sockets directly from BufSizes and are unaffected by this function.
//
// SndBuf is deliberately left at 0 (kernel autotuning) unless the operator sets
// an explicit override. Pinning SO_SNDBUF to a large fixed value turns the
// socket send buffer into a multi-megabyte standing FIFO: under any carrier
// congestion the kernel accepts megabytes of app data and drains them slowly,
// so latency-sensitive packets (and mux's high-priority frames) sit behind
// seconds of already-buffered bytes — classic bufferbloat, and the direct cause
// of the ~10 s tunnelled ping. Linux tcp_wmem autotuning tracks the BDP, so BBR
// still gets at least a bandwidth-delay-product of buffer (no throughput loss)
// without the standing queue.
//
// RcvBuf is left to autotuning for the opposite reason. Pinning SO_RCVBUF does
// not cause bufferbloat, but it does switch off tcp_moderate_rcvbuf, and from
// then on the receive window can never exceed what was pinned. The resource
// profile pinned 256 KiB, which over a 100 ms route is a 21 Mbit/s ceiling on
// one link no matter what the path can carry — and it lands on whichever
// direction flows *into* that server, which is why upload suffered while
// download, spread over many connections, did not. The kernel's autotuner
// tracks the bandwidth-delay product and grows to tcp_rmem's ceiling, so it can
// only do better than a fixed number chosen from how much RAM the box has.
//
// An explicit override still pins both, for an operator who has measured their
// path and wants a specific size.
func LinkOptions(profile string, sndOverride, rcvOverride int) Options {
	o := Options{
		SndBuf:      sndOverride, // 0 => kernel autotune; only an explicit override pins it
		RcvBuf:      rcvOverride, // likewise: pinning it would cap the receive window
		UserTimeout: 12 * time.Second,
		Keepalive:   10 * time.Second,
		BBR:         true,
		// Not applied when the operator pins SO_SNDBUF: they have asked for a
		// specific send queue and the two knobs would fight.
		NotSentLowat: notSentLowat,
	}
	if sndOverride > 0 {
		o.NotSentLowat = 0
	}
	if profile == "resource" {
		// Fewer wakeups on tiny VPS.
		o.Keepalive = 20 * time.Second
	}
	return o
}

// BufSizes resolves send/recv socket buffer sizes for a profile. Non-zero
// overrides take precedence. A return of 0 means "leave the OS default".
func BufSizes(profile string, sndOverride, rcvOverride int) (snd, rcv int) {
	// Datagram carriers only (TCP links leave both to the kernel — see
	// LinkOptions). The two sides are sized differently on purpose.
	//
	// The receive side is generous. A datagram socket has no autotuning, traffic
	// arrives in bursts, and a burst larger than the socket queue is dropped by
	// the kernel before this process sees it — packet loss the tunnel inflicts on
	// itself, on carriers picked precisely because the path is already difficult.
	// An over-large receive queue costs only memory; it cannot add delay, because
	// nothing waits in it.
	//
	// The send side stays small. There the queue is delay: bytes sitting in the
	// socket are bytes the scheduler can no longer reorder, so an express packet
	// ends up behind whatever bulk was handed down earlier. Queueing belongs in
	// the tunnel's own scheduler, where CoDel can measure it.
	switch profile {
	case "fast":
		snd, rcv = 4<<20, 8<<20
	case "resource":
		snd, rcv = 256<<10, 2<<20 // small send queue, room to absorb bursts
	default: // balance
		snd, rcv = 1<<20, 4<<20
	}
	if sndOverride > 0 {
		snd = sndOverride
	}
	if rcvOverride > 0 {
		rcv = rcvOverride
	}
	return snd, rcv
}
