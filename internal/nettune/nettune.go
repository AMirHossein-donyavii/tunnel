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
	QuickAck    bool          // TCP_QUICKACK: disable delayed ACKs (lower latency)
	BBR         bool          // request BBR congestion control
}

// LinkOptions builds recommended options for a tunnel link from the profile,
// with explicit buffer overrides.
func LinkOptions(profile string, sndOverride, rcvOverride int) Options {
	snd, rcv := BufSizes(profile, sndOverride, rcvOverride)
	o := Options{
		SndBuf:      snd,
		RcvBuf:      rcv,
		UserTimeout: 20 * time.Second,
		Keepalive:   15 * time.Second,
		QuickAck:    true,
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
