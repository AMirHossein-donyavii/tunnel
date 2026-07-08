package muxeng

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/emergency-tunnel/et/internal/crypto"
	"github.com/emergency-tunnel/et/internal/mux"
)

// delayConn wraps a net.Conn and adds a fixed one-way delay per write, to
// simulate propagation latency on a long-distance link.
type delayConn struct {
	net.Conn
	d time.Duration
}

func (c delayConn) Write(p []byte) (int, error) {
	time.Sleep(c.d)
	return c.Conn.Write(p)
}

func pipeWithDelay(d time.Duration) (net.Conn, net.Conn) {
	c1, c2 := net.Pipe()
	if d == 0 {
		return c1, c2
	}
	return delayConn{c1, d}, delayConn{c2, d}
}


// --- mux: new connection = one stream on an existing session -----------------

func benchMuxSetup(b *testing.B, rtt time.Duration) {
	c1, c2 := pipeWithDelay(rtt / 2)
	cs := mux.Client(c1, mux.Config{AcceptBacklog: 256})
	ss := mux.Server(c2, mux.Config{AcceptBacklog: 256})
	defer cs.Close()
	defer ss.Close()
	go func() {
		for {
			st, err := ss.AcceptStream()
			if err != nil {
				return
			}
			go func(st *mux.Stream) { _, _ = io.Copy(st, st); st.Close() }(st)
		}
	}()
	req := make([]byte, 64)
	buf := make([]byte, 64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st, err := cs.OpenStream([]byte{0x1f, 0x90}, false)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := st.Write(req); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(st, buf); err != nil {
			b.Fatal(err)
		}
		st.Close()
	}
}

// --- baseline: new connection = a full crypto handshake per connection -------
// (models a naive per-connection handshake when no warm link is available).

func benchHandshakeSetup(b *testing.B, rtt time.Duration) {
	req := make([]byte, 64)
	buf := make([]byte, 64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c1, c2 := pipeWithDelay(rtt / 2)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			sc, err := crypto.ServerHandshake(c2, "chacha20-poly1305")
			if err != nil {
				return
			}
			io.CopyN(sc, sc, 64) // echo one request
			sc.Close()
		}()
		cc, err := crypto.ClientHandshake(c1, "chacha20-poly1305")
		if err != nil {
			b.Fatal(err)
		}
		if _, err := cc.Write(req); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(cc, buf); err != nil {
			b.Fatal(err)
		}
		cc.Close()
		wg.Wait()
	}
}

func BenchmarkConnSetup_Mux_0ms(b *testing.B)        { benchMuxSetup(b, 0) }
func BenchmarkConnSetup_Handshake_0ms(b *testing.B)  { benchHandshakeSetup(b, 0) }
func BenchmarkConnSetup_Mux_20ms(b *testing.B)       { benchMuxSetup(b, 20*time.Millisecond) }
func BenchmarkConnSetup_Handshake_20ms(b *testing.B) { benchHandshakeSetup(b, 20*time.Millisecond) }

// --- throughput on an established mux stream ---------------------------------

func BenchmarkThroughput_MuxStream(b *testing.B) {
	c1, c2 := net.Pipe()
	cs := mux.Client(c1, mux.Config{AcceptBacklog: 4})
	ss := mux.Server(c2, mux.Config{AcceptBacklog: 4})
	defer cs.Close()
	defer ss.Close()
	// Server drains whatever arrives.
	go func() {
		st, err := ss.AcceptStream()
		if err != nil {
			return
		}
		io.Copy(io.Discard, st)
	}()
	st, err := cs.OpenStream(nil, false)
	if err != nil {
		b.Fatal(err)
	}
	chunk := make([]byte, 32*1024)
	b.SetBytes(int64(len(chunk)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
}
