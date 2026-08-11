package rudp

import (
	"testing"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
)

func TestFECSweep(t *testing.T) {
	const delay = 50 * time.Millisecond
	const window = 3 * time.Second
	mbit := func(b int64) float64 { return float64(b) * 8 / window.Seconds() / 1e6 }
	for _, loss := range []float64{0.01, 0.03, 0.08, 0.15} {
		p := transferThrough(t, config.Config{}, loss, delay, window)
		c := transferThrough(t, config.Config{FECData: 10, FECParity: 3}, loss, delay, window)
		t.Logf("loss %4.0f%%  no-FEC %6.2f Mbit/s   FEC 10:3 %6.2f Mbit/s   %.2fx",
			loss*100, mbit(p), mbit(c), float64(c)/float64(p))
	}
}
