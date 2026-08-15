//go:build linux

package l3

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
)

// How fast can one carrier link actually move bytes, with no path in the way?
//
// On a real path this tunnel tops out well below what another implementation
// reaches over the same route, and the loss figures say loss is not what is
// holding it there. That leaves a ceiling in this code. Loopback removes the
// path from the question: whatever this reports is what the carrier itself can
// do, and anything close to the observed real-path rate means the ceiling is
// here rather than out there.
func BenchmarkCarrierThroughput(b *testing.B) {
	for _, mode := range []string{config.TunModeICMP, config.TunModeUDP} {
		b.Run(mode, func(b *testing.B) {
			cfg := &config.Config{TunnelPort: 6100, Cipher: "aes-256-gcm",
				Profile: "fast", Peer: "127.0.0.1"}
			log := logx.New(io.Discard, logx.ERROR)

			var ld linkDialer
			var ll linkListener
			var err error
			switch mode {
			case config.TunModeICMP:
				_, ll, err = newICMPCarrier(mode, cfg, false, cfg.Cipher, log)
				if err != nil {
					b.Skipf("raw sockets unavailable: %v", err)
				}
				ld, _, _ = newICMPCarrier(mode, cfg, true, cfg.Cipher, log)
			default:
				ll, err = newUDPListener(cfg.TunnelPort, 0, 0, cfg.Cipher)
				if err != nil {
					b.Skipf("udp listener: %v", err)
				}
				ld = &udpLinkDialer{addr: "127.0.0.1:6100", cipher: cfg.Cipher}
			}
			defer ll.Close()
			defer ld.Close()

			type acc struct {
				lk  link
				err error
			}
			ch := make(chan acc, 1)
			go func() { lk, err := ll.AcceptLink(); ch <- acc{lk, err} }()

			client, err := ld.DialLink(context.Background())
			if err != nil {
				b.Fatalf("dial: %v", err)
			}
			defer client.Close()
			a := <-ch
			if a.err != nil {
				b.Fatalf("accept: %v", a.err)
			}
			defer a.lk.Close()

			// One full frame, as the engine would send it.
			frame := make([]byte, dgramMaxFrame)
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					_ = a.lk.SetReadDeadline(time.Now().Add(2 * time.Second))
					if _, err := a.lk.ReadFrame(); err != nil {
						return
					}
				}
			}()

			b.SetBytes(int64(len(frame)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := client.WriteFrame(frame); err != nil {
					b.Fatalf("write %d: %v", i, err)
				}
			}
			b.StopTimer()
		})
	}
}

// The carrier alone is fast. This puts the scheduler in front of it — the real
// send path: a packet is pushed into the txQueue, tunToLink drains it, batches
// it and hands it to the link. If the ceiling is not in the carrier, it is
// somewhere in here.
func BenchmarkSendPathWithScheduler(b *testing.B) {
	e := testEngine(b2t(b))
	e.hbInterval = time.Hour
	tq := newTxQueue(channelDefault("fast"), 1320, e.pool, &e.qstats)

	la, lb := memLinkPair(4096)
	defer la.Close()
	defer lb.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Drain the far end as fast as it will go, so the benchmark measures the
	// sender rather than a full pipe.
	go func() {
		for {
			if _, err := lb.ReadFrame(); err != nil {
				return
			}
		}
	}()
	go e.tunToLink(ctx, tq, la, &pumpState{ctlOut: make(chan ctlMsg, 8)})

	pkt := make([]byte, 1320)
	pkt[0] = 0x45
	pkt[9] = protoTCP

	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := e.pool.get()
		copy(p.b, pkt)
		p.n = len(pkt)
		tq.push(p)
	}
	b.StopTimer()
}

// b2t adapts a *testing.B where a helper wants a *testing.T. The helper only
// uses Helper(), so this is safe and keeps one engine constructor.
func b2t(b *testing.B) *testing.T { return &testing.T{} }
