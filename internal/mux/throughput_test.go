package mux

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// --- delayed async link ------------------------------------------------------
//
// delayPipe is an in-memory net.Conn pair with a constant one-way propagation
// delay and a large in-flight buffer, so a single stream's throughput is bound
// by the mux flow-control window (bandwidth-delay product) rather than by a
// synchronous pipe. It models a fat long-distance link for window benchmarking.

type timedChunk struct {
	t time.Time
	p []byte
}

type dpEnd struct {
	send   chan<- timedChunk
	recv   <-chan []byte
	rbuf   []byte
	closed chan struct{}
	once   *sync.Once
}

func newDelayPipe(delay time.Duration, capChunks int) (net.Conn, net.Conn) {
	a := make(chan timedChunk, capChunks)
	b := make(chan timedChunk, capChunks)
	ra := make(chan []byte, capChunks)
	rb := make(chan []byte, capChunks)
	closed := make(chan struct{})
	go relay(a, rb, delay, closed) // A -> B
	go relay(b, ra, delay, closed) // B -> A
	var once sync.Once
	e1 := &dpEnd{send: a, recv: ra, closed: closed, once: &once}
	e2 := &dpEnd{send: b, recv: rb, closed: closed, once: &once}
	return e1, e2
}

// relay delivers each chunk at its enqueue time + delay. Because the enqueue
// timestamp is captured on Write, chunks pipeline: only the first pays the full
// delay, the rest stream out at wire speed (bounded by the channel buffer).
func relay(in <-chan timedChunk, out chan<- []byte, delay time.Duration, closed chan struct{}) {
	for {
		select {
		case c := <-in:
			if d := time.Until(c.t.Add(delay)); d > 0 {
				select {
				case <-time.After(d):
				case <-closed:
					return
				}
			}
			select {
			case out <- c.p:
			case <-closed:
				return
			}
		case <-closed:
			return
		}
	}
}

func (e *dpEnd) Read(p []byte) (int, error) {
	if len(e.rbuf) == 0 {
		select {
		case b, ok := <-e.recv:
			if !ok {
				return 0, io.EOF
			}
			e.rbuf = b
		case <-e.closed:
			return 0, io.EOF
		}
	}
	n := copy(p, e.rbuf)
	e.rbuf = e.rbuf[n:]
	return n, nil
}

func (e *dpEnd) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case e.send <- timedChunk{time.Now(), cp}:
		return len(p), nil
	case <-e.closed:
		return 0, net.ErrClosed
	}
}

func (e *dpEnd) Close() error {
	e.once.Do(func() { close(e.closed) })
	return nil
}
func (e *dpEnd) LocalAddr() net.Addr                { return dummyAddr{} }
func (e *dpEnd) RemoteAddr() net.Addr               { return dummyAddr{} }
func (e *dpEnd) SetDeadline(t time.Time) error      { return nil }
func (e *dpEnd) SetReadDeadline(t time.Time) error  { return nil }
func (e *dpEnd) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "delaypipe" }
func (dummyAddr) String() string  { return "delaypipe" }

// --- window throughput -------------------------------------------------------

// measureThroughput opens one stream over a delayed link and returns the
// achieved single-stream throughput in MiB/s for the given receive window.
func measureThroughput(window int, delay time.Duration, total int) float64 {
	c1, c2 := newDelayPipe(delay, 4096)
	cfg := Config{Window: window, AcceptBacklog: 4}
	cs := Client(c1, cfg)
	ss := Server(c2, cfg)
	defer cs.Close()
	defer ss.Close()

	done := make(chan int64, 1)
	go func() {
		st, err := ss.AcceptStream()
		if err != nil {
			done <- 0
			return
		}
		n, _ := io.Copy(io.Discard, st)
		done <- n
	}()

	st, err := cs.OpenStream(nil, false)
	if err != nil {
		return 0
	}
	chunk := make([]byte, 32*1024)
	start := time.Now()
	sent := 0
	for sent < total {
		n, err := st.Write(chunk)
		if err != nil {
			break
		}
		sent += n
	}
	st.Close()
	<-done
	elapsed := time.Since(start)
	return float64(sent) / (1024 * 1024) / elapsed.Seconds()
}

// TestWindowScalesThroughput asserts that a larger receive window yields higher
// single-stream throughput on a high-BDP link — the concrete win behind the
// per-profile window sizing. It is a correctness guard, not a micro-benchmark.
func TestWindowScalesThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("skips the timed throughput comparison in -short")
	}
	const delay = 5 * time.Millisecond // 10 ms RTT
	const total = 8 * 1024 * 1024

	small := measureThroughput(512*1024, delay, total)
	large := measureThroughput(4*1024*1024, delay, total)
	t.Logf("single-stream @10ms RTT: 512KiB window = %.1f MiB/s, 4MiB window = %.1f MiB/s (%.1fx)",
		small, large, large/small)
	if large <= small*1.5 {
		t.Fatalf("expected the larger window to be markedly faster; got small=%.1f large=%.1f MiB/s", small, large)
	}
}

// BenchmarkWindowThroughput reports single-stream throughput across window sizes
// on a 10 ms-RTT link, documenting the window -> throughput relationship.
func BenchmarkWindowThroughput(b *testing.B) {
	for _, w := range []int{512 * 1024, 2 * 1024 * 1024, 4 * 1024 * 1024} {
		b.Run(fmt.Sprintf("win=%dKiB", w/1024), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				measureThroughput(w, 5*time.Millisecond, 4*1024*1024)
			}
		})
	}
}
