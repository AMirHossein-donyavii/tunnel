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
}

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
		UserTimeout: 20 * time.Second,
		Keepalive:   15 * time.Second,
		BBR:         true,
	}
	if profile == "resource" {
		// Fewer wakeups on tiny VPS.
		o.Keepalive = 30 * time.Second
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
