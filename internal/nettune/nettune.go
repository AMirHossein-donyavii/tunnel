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
// without the standing queue. The receive buffer keeps its profile size — a
// large RcvBuf does not cause sender-side bufferbloat.
func LinkOptions(profile string, sndOverride, rcvOverride int) Options {
	_, rcv := BufSizes(profile, 0, rcvOverride)
	o := Options{
		SndBuf:      sndOverride, // 0 => kernel autotune; only an explicit override pins it
		RcvBuf:      rcv,
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
	switch profile {
	case "fast":
		snd, rcv = 4<<20, 4<<20 // 4 MiB: maximise throughput on roomy links
	case "resource":
		snd, rcv = 256<<10, 256<<10 // 256 KiB: minimise memory on tiny VPS
	default: // balance
		snd, rcv = 1<<20, 1<<20 // 1 MiB
	}
	if sndOverride > 0 {
		snd = sndOverride
	}
	if rcvOverride > 0 {
		rcv = rcvOverride
	}
	return snd, rcv
}
