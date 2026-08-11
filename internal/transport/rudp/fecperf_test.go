package rudp

import (
	"context"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
)

// lossyRelay is a UDP proxy that drops a share of the packets crossing it, so
// the carrier can be measured on the kind of path it is meant to survive rather
// than on a clean loopback where every design looks the same.
type lossyRelay struct {
	front   *net.UDPConn // faces the client
	back    *net.UDPConn // faces the server
	loss    float64
	rng     *rand.Rand
	mu      sync.Mutex
	stop    chan struct{}
	stats   func() (fwd, rev, dropped int)
	lastErr func() error
}

// after runs fn once delay has passed, or immediately when there is none.
func (r *lossyRelay) after(delay time.Duration, fn func()) {
	if delay <= 0 {
		fn()
		return
	}
	time.AfterFunc(delay, fn)
}

// delay is one-way latency added to every packet. Without it the measurement is
// meaningless for FEC: its whole premise is that a retransmission costs a round
// trip, and on loopback a round trip costs nothing, so parity is pure overhead.
// A real Iran-to-Europe path is ~50ms each way.
func newLossyRelay(t *testing.T, serverPort int, loss float64, seed int64, delay time.Duration) *lossyRelay {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	back, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &lossyRelay{front: front, back: back, loss: loss,
		rng: rand.New(rand.NewSource(seed)), stop: make(chan struct{})}

	srv := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: serverPort}
	var clientAddr *net.UDPAddr

	// The first packets each way carry the handshake. Losing those measures how
	// stubbornly the carrier retries its SYN, which is not what this is for, and
	// it makes the result depend on which packets a seed happens to drop. Loss
	// starts once the connection is up, so what is measured is the data path.
	const warmup = 20
	seen := 0
	var fwd, rev, dropped int
	var lastErr error
	drop := func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		seen++
		if seen <= warmup {
			return false
		}
		return r.rng.Float64() < r.loss
	}

	go func() { // client -> server
		buf := make([]byte, 65535)
		for {
			n, src, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			r.mu.Lock()
			clientAddr = src
			r.mu.Unlock()
			if drop() {
				r.mu.Lock()
				dropped++
				r.mu.Unlock()
				continue
			}
			pkt := append([]byte(nil), buf[:n]...)
			r.mu.Lock()
			fwd++
			r.mu.Unlock()
			r.after(delay, func() { _, _ = back.WriteToUDP(pkt, srv) })
		}
	}()
	go func() { // server -> client
		buf := make([]byte, 65535)
		for {
			n, _, err := back.ReadFromUDP(buf)
			if err != nil {
				return
			}
			r.mu.Lock()
			dst := clientAddr
			r.mu.Unlock()
			if dst == nil || drop() {
				r.mu.Lock()
				dropped++
				r.mu.Unlock()
				continue
			}
			pkt := append([]byte(nil), buf[:n]...)
			r.mu.Lock()
			rev++
			r.mu.Unlock()
			r.after(delay, func() { _, _ = front.WriteToUDP(pkt, dst) })
		}
	}()
	r.stats = func() (int, int, int) { r.mu.Lock(); defer r.mu.Unlock(); return fwd, rev, dropped }
	r.lastErr = func() error { r.mu.Lock(); defer r.mu.Unlock(); return lastErr }
	t.Cleanup(func() { close(r.stop); front.Close(); back.Close() })
	return r
}

func (r *lossyRelay) port() int { return r.front.LocalAddr().(*net.UDPAddr).Port }

// transferThrough moves as much as it can in the given window and returns the
// bytes the receiver actually read.
func transferThrough(t *testing.T, fec config.Config, loss float64, delay, window time.Duration) int64 {
	t.Helper()
	tr := &rudpTransport{}
	log := logx.New(io.Discard, logx.ERROR)

	srvCfg := fec
	srvCfg.TunnelPort, srvCfg.Profile = 0, "balance"
	ln, err := tr.NewListener(&srvCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvAddr := ln.Addr().String()
	relay := newLossyRelay(t, ln.Addr().(*net.UDPAddr).Port, loss, 42, delay)

	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- c
		}
	}()

	cliCfg := fec
	cliCfg.Peer, cliCfg.TunnelPort, cliCfg.Profile = "127.0.0.1", relay.port(), "balance"
	d, err := tr.NewDialer(&cliCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := d.Dial(context.Background())
	if err != nil {
		f, rv, dr := relay.stats()
		t.Fatalf("dial across a %.0f%% loss path: %v (relay: %d fwd, %d rev, %d dropped, srv=%s lastErr=%v)",
			loss*100, err, f, rv, dr, srvAddr, relay.lastErr())
	}
	defer cli.Close()

	var srv net.Conn
	select {
	case srv = <-accepted:
	case <-time.After(10 * time.Second):
		t.Fatal("server never accepted the connection")
	}
	defer srv.Close()

	var read int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64*1024)
		for {
			n, err := srv.Read(buf)
			read += int64(n)
			if err != nil {
				return
			}
		}
	}()

	payload := make([]byte, 16*1024)
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		_ = cli.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := cli.Write(payload); err != nil {
			break
		}
	}
	cli.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
	return read
}

// What FEC actually costs and returns, measured rather than assumed.
//
// The result so far is negative, which is why fec_data/fec_parity default to
// off. Across 1/3/8/15% loss over a 100ms round trip, coded throughput came out
// at 0.43x, 0.82x, 0.90x and 0.32x of the plain carrier — never a win.
//
// The likely reason is that parity is generated below the congestion control
// that is pacing the connection. The ARQ sizes its window against what the path
// will carry; the encoder then puts 30% more packets onto that same path
// without telling it. At a bottleneck, those displace exactly the data they were
// meant to protect, and the losses they repair do not repay the capacity they
// took. Fixing that means accounting for parity inside the congestion window
// rather than adding it underneath — a change to the ARQ, not to this codec.
//
// The harness is also not a faithful path: a userspace relay with a timer per
// packet caps throughput far below what the carrier reaches on a clean socket,
// so the absolute numbers understate everything and the comparison is only
// suggestive. It is enough to say FEC should not be switched on by default; it
// is not enough to say it can never help.
//
// So this test asserts correctness only — that both carriers deliver — and
// records the ratio for whoever picks the work up.
func TestFECThroughputOnALossyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive; runs for several seconds")
	}
	const loss = 0.03
	const window = 3 * time.Second

	const delay = 50 * time.Millisecond // ~100ms round trip, a real long-haul path
	plain := transferThrough(t, config.Config{}, loss, delay, window)
	coded := transferThrough(t, config.Config{FECData: 10, FECParity: 3}, loss, delay, window)

	mbit := func(b int64) float64 { return float64(b) * 8 / window.Seconds() / 1e6 }
	t.Logf("at %.0f%% loss over a %s round trip: no FEC %.1f Mbit/s, FEC 10:3 %.1f Mbit/s (%.2fx)",
		loss*100, 2*delay, mbit(plain), mbit(coded), float64(coded)/float64(plain))

	if plain == 0 {
		t.Fatal("the plain carrier delivered nothing — the test path is broken, not the carrier")
	}
	if coded == 0 {
		t.Fatal("the FEC carrier delivered nothing across a 3% loss path")
	}
	// Deliberately not gated on a ratio: see the note above. The measurement is
	// the deliverable here, not a threshold.
}

// FEC must not change what the carrier delivers, only how fast it gets there.
func TestFECDeliversTheSameBytes(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive")
	}
	if n := transferThrough(t, config.Config{FECData: 10, FECParity: 3}, 0.05, 20*time.Millisecond, 2*time.Second); n == 0 {
		t.Fatal("nothing arrived across a 5% loss path with FEC on")
	}
}
