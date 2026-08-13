package l3

import (
	"bytes"
	"errors"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/emergency-tunnel/et/internal/crypto"
)

// lossyConn drops a fixed fraction of the datagrams written through it, the way
// a path that polices ICMP does.
type lossyConn struct {
	mu     sync.Mutex
	rng    *rand.Rand
	loss   float64
	queue  [][]byte
	sent   int
	closed chan struct{}
}

func newLossyConn(loss float64, seed int64) *lossyConn {
	return &lossyConn{rng: rand.New(rand.NewSource(seed)), loss: loss,
		closed: make(chan struct{})}
}

func (c *lossyConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.sent++
	drop := c.rng.Float64() < c.loss
	if !drop {
		c.queue = append(c.queue, append([]byte(nil), p...))
	}
	c.mu.Unlock()
	return len(p), nil
}

var errEmpty = errors.New("empty")

// Read is non-blocking: the tests drive writes and reads in lockstep, and a
// blocking read would only add wall-clock time.
func (c *lossyConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.queue) == 0 {
		return 0, errEmpty
	}
	n := copy(p, c.queue[0])
	c.queue = c.queue[1:]
	return n, nil
}

func (c *lossyConn) Close() error                       { close(c.closed); return nil }
func (c *lossyConn) LocalAddr() net.Addr                { return nil }
func (c *lossyConn) RemoteAddr() net.Addr               { return nil }
func (c *lossyConn) SetDeadline(time.Time) error        { return nil }
func (c *lossyConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *lossyConn) SetWriteDeadline(t time.Time) error { return nil }

func datagramPair(t *testing.T, conn net.Conn) (*crypto.Datagram, *crypto.Datagram) {
	t.Helper()
	// Two Datagrams keyed alike, one sealing and one opening.
	key := bytes.Repeat([]byte{7}, 32)
	send, err := crypto.NewDatagramForTest("aes-256-gcm", key, key)
	if err != nil {
		t.Fatal(err)
	}
	recv, err := crypto.NewDatagramForTest("aes-256-gcm", key, key)
	if err != nil {
		t.Fatal(err)
	}
	return send, recv
}

// A datagram carrier does not retransmit, so what the path drops is gone. Inner
// TCP recovers on its own; a ping through the tunnel, a pure ACK and — worst of
// all — a heartbeat do not. A heartbeat lost is a step towards the liveness
// monitor declaring the link dead and cycling it, which drops everything in
// flight. That is the "ping through the VPN times out sometimes" the user sees
// on a path that polices ICMP.
//
// Small frames are therefore sent twice. This measures what that buys.
func TestSmallFramesSurviveLossFarBetterWhenSentTwice(t *testing.T) {
	const (
		frames = 4000
		loss   = 0.10
	)
	heartbeat := make([]byte, 12) // what a control frame actually looks like

	run := func(dup bool) (delivered int) {
		conn := newLossyConn(loss, 42)
		defer conn.Close()
		send, recv := datagramPair(t, conn)
		w := &datagramLink{conn: conn, dg: send, wbuf: nil}
		r := &datagramLink{conn: conn, dg: recv,
			rbuf: make([]byte, dgramMaxFrame+crypto.DatagramOverhead+64),
			pbuf: make([]byte, 0, dgramMaxFrame+64)}

		for i := 0; i < frames; i++ {
			// Write directly so the duplication can be turned off for the
			// comparison, using the same sealed bytes the real path uses.
			w.wbuf = w.dg.Seal(w.wbuf[:0], heartbeat)
			_, _ = conn.Write(w.wbuf)
			if dup {
				_, _ = conn.Write(w.wbuf)
			}
			for {
				if _, err := r.ReadFrame(); err != nil {
					break
				}
				delivered++
			}
		}
		return delivered
	}

	single := run(false)
	doubled := run(true)

	lossSingle := 100 * float64(frames-single) / float64(frames)
	lossDoubled := 100 * float64(frames-doubled) / float64(frames)
	t.Logf("at %.0f%% path loss: one copy lost %.2f%% of frames, two copies lost %.2f%%",
		loss*100, lossSingle, lossDoubled)

	if doubled <= single {
		t.Fatalf("duplication delivered %d frames, no better than %d", doubled, single)
	}
	// p squared, with room for the sample size.
	if lossDoubled > lossSingle*lossSingle/100*3 {
		t.Fatalf("duplicated frames lost %.2f%%, want about %.2f%% (p squared)",
			lossDoubled, lossSingle*lossSingle/100)
	}
	// And the duplicate must never reach the caller twice: the replay window
	// drops it, which is what stops every small packet being injected into the
	// TUN device twice and read by inner TCP as duplicate ACKs.
	if doubled > frames {
		t.Fatalf("%d frames delivered from %d sent — the copy was delivered as a "+
			"second frame instead of being dropped as a replay", doubled, frames)
	}
}

// A full-size frame must not be duplicated: that would double the tunnel's
// bandwidth for no benefit, since bulk loss is what inner TCP already handles.
func TestLargeFramesAreNotDuplicated(t *testing.T) {
	conn := newLossyConn(0, 1)
	defer conn.Close()
	send, _ := datagramPair(t, conn)
	l := &datagramLink{conn: conn, dg: send}

	before := conn.sent
	if err := l.WriteFrame(bytes.Repeat([]byte("x"), dupThreshold+1)); err != nil {
		t.Fatal(err)
	}
	if got := conn.sent - before; got != 1 {
		t.Fatalf("a %d-byte frame was written %d times; only frames of %d bytes or less "+
			"are worth duplicating", dupThreshold+1, got, dupThreshold)
	}

	before = conn.sent
	if err := l.WriteFrame(bytes.Repeat([]byte("x"), dupThreshold)); err != nil {
		t.Fatal(err)
	}
	if got := conn.sent - before; got != 2 {
		t.Fatalf("a %d-byte frame was written %d times, want 2", dupThreshold, got)
	}
}

// The duplicate arrives as a replayed counter, which is the expected case and
// must not count towards the "peer's keys do not match" limit — on an idle
// tunnel every frame is small, so counting them would walk that limit up and
// tear down a perfectly healthy link.
func TestDuplicatesDoNotCountAsBadDatagrams(t *testing.T) {
	conn := newLossyConn(0, 1)
	defer conn.Close()
	send, recv := datagramPair(t, conn)
	w := &datagramLink{conn: conn, dg: send}
	r := &datagramLink{conn: conn, dg: recv,
		rbuf: make([]byte, dgramMaxFrame+crypto.DatagramOverhead+64),
		pbuf: make([]byte, 0, dgramMaxFrame+64)}

	small := make([]byte, 16)
	for i := 0; i < maxBadDatagrams*4; i++ {
		if err := w.WriteFrame(small); err != nil {
			t.Fatal(err)
		}
		if _, err := r.ReadFrame(); err != nil {
			t.Fatalf("frame %d: %v — the link gave up, having counted its own "+
				"duplicates as evidence the peer's keys are wrong", i, err)
		}
	}
	if r.bad != 0 {
		t.Fatalf("%d duplicates were counted as undecryptable datagrams", r.bad)
	}
}

// refusingConn fails a set number of writes with a given errno, then succeeds.
type refusingConn struct {
	lossyConn
	fails int
	err   error
}

func (c *refusingConn) Write(p []byte) (int, error) {
	if c.fails > 0 {
		c.fails--
		return 0, c.err
	}
	return c.lossyConn.Write(p)
}

// A raw ICMP socket refuses a send routinely: ENOBUFS when the interface queue
// is momentarily full, EPERM when a firewall rate-limiter drops this packet.
// Treating that as the link being dead cycled the carrier — everything in
// flight lost, a re-dial, a visible stall — for something that costs one frame.
func TestATransientSendFailureCostsOneFrameNotTheLink(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"interface queue full", syscall.ENOBUFS},
		{"firewall rate-limited this packet", syscall.EPERM},
		{"frame too big for the path", syscall.EMSGSIZE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &refusingConn{lossyConn: *newLossyConn(0, 1), fails: 5, err: tc.err}
			send, _ := datagramPair(t, conn)
			l := &datagramLink{conn: conn, dg: send}

			for i := 0; i < 5; i++ {
				if err := l.WriteFrame(make([]byte, 800)); err != nil {
					t.Fatalf("send %d returned %v — the link is torn down and re-dialed "+
						"for one frame the socket would not take", i, err)
				}
			}
			// And it must recover cleanly once the socket does.
			if err := l.WriteFrame(make([]byte, 800)); err != nil {
				t.Fatalf("the link stayed broken after the socket recovered: %v", err)
			}
			if l.badWrites != 0 {
				t.Fatalf("the consecutive-failure count did not reset on success (%d)", l.badWrites)
			}
		})
	}
}

// A socket that refuses every send is not transient, and carrying on would spin.
func TestAPermanentlyRefusingSocketStillEndsTheLink(t *testing.T) {
	conn := &refusingConn{lossyConn: *newLossyConn(0, 1), fails: 1 << 30, err: syscall.ENOBUFS}
	send, _ := datagramPair(t, conn)
	l := &datagramLink{conn: conn, dg: send}

	var err error
	for i := 0; i <= maxBadWrites+1; i++ {
		if err = l.WriteFrame(make([]byte, 800)); err != nil {
			break
		}
	}
	if err == nil {
		t.Fatal("a socket refusing every send was tolerated forever")
	}
}

// An error that is not transient must end the link at once: a closed socket is
// not going to start working.
func TestANonTransientSendFailureEndsTheLinkImmediately(t *testing.T) {
	conn := &refusingConn{lossyConn: *newLossyConn(0, 1), fails: 1, err: net.ErrClosed}
	send, _ := datagramPair(t, conn)
	l := &datagramLink{conn: conn, dg: send}
	if err := l.WriteFrame(make([]byte, 800)); err == nil {
		t.Fatal("a closed socket was treated as a transient failure")
	}
}
