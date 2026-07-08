// Package nettune applies transport-level performance tuning to tunnel links:
// socket buffer sizes, TCP_NODELAY, and (on Linux) the BBR congestion control
// algorithm. Buffer sizing follows the performance profile unless overridden.
package nettune

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
