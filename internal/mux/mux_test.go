package mux

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func testCfg() Config { return Config{KeepAlive: 0, AcceptBacklog: 256} }

func pair() (*Session, *Session) {
	c1, c2 := net.Pipe()
	return Client(c1, testCfg()), Server(c2, testCfg())
}

// echoServer accepts streams and echoes each until the peer half-closes.
func echoServer(s *Session) {
	for {
		st, err := s.AcceptStream()
		if err != nil {
			return
		}
		go func(st *Stream) {
			_, _ = io.Copy(st, st)
			_ = st.Close()
		}(st)
	}
}

func TestEchoRoundTrip(t *testing.T) {
	cs, ss := pair()
	defer cs.Close()
	defer ss.Close()
	go echoServer(ss)

	st, err := cs.OpenStream([]byte("dest:9000"), false)
	if err != nil {
		t.Fatal(err)
	}
	msg := bytes.Repeat([]byte("emergency-tunnel-mux "), 500) // ~10KB
	go func() {
		_, _ = st.Write(msg)
		_ = st.Close()
	}()
	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: got %d bytes want %d", len(got), len(msg))
	}
}

func TestSYNDestHint(t *testing.T) {
	cs, ss := pair()
	defer cs.Close()
	defer ss.Close()
	want := []byte("remote:8443")
	go func() { _, _ = cs.OpenStream(want, false) }()
	st, err := ss.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(st.Dest(), want) {
		t.Fatalf("dest hint: got %q want %q", st.Dest(), want)
	}
}

func TestConcurrentStreams(t *testing.T) {
	cs, ss := pair()
	defer cs.Close()
	defer ss.Close()
	go echoServer(ss)

	const n = 64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			st, err := cs.OpenStream(nil, i%4 == 0) // mix priorities
			if err != nil {
				t.Errorf("open: %v", err)
				return
			}
			payload := make([]byte, 4096+i*37)
			_, _ = rand.Read(payload)
			go func() {
				_, _ = st.Write(payload)
				_ = st.Close()
			}()
			got, err := io.ReadAll(st)
			if err != nil {
				t.Errorf("read: %v", err)
				return
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("stream %d mismatch: %d/%d bytes", i, len(got), len(payload))
			}
		}(i)
	}
	wg.Wait()
}

// TestFlowControlLargeTransfer moves far more than one window through a single
// stream, exercising WINDOW_UPDATE replenishment end-to-end.
func TestFlowControlLargeTransfer(t *testing.T) {
	cs, ss := pair()
	defer cs.Close()
	defer ss.Close()
	go echoServer(ss)

	st, err := cs.OpenStream(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	const total = 4 * 1024 * 1024 // 4 MiB >> 256 KiB window
	payload := make([]byte, total)
	_, _ = rand.Read(payload)

	go func() {
		_, _ = st.Write(payload)
		_ = st.Close()
	}()
	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("large transfer mismatch: %d/%d", len(got), total)
	}
}

func TestPingRTT(t *testing.T) {
	cs, ss := pair()
	defer cs.Close()
	defer ss.Close()
	rtt, err := cs.Ping(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if rtt <= 0 {
		t.Fatalf("expected positive rtt, got %v", rtt)
	}
	if cs.LastRTT() != rtt {
		t.Fatalf("LastRTT mismatch")
	}
}

// TestStreamReaping verifies that fully-closed streams are removed from the
// session map (no leak for long-lived sessions with many short streams).
func TestStreamReaping(t *testing.T) {
	cs, ss := pair()
	defer cs.Close()
	defer ss.Close()
	go echoServer(ss)

	for i := 0; i < 50; i++ {
		st, err := cs.OpenStream(nil, false)
		if err != nil {
			t.Fatal(err)
		}
		go func() { _, _ = st.Write([]byte("ping")); _ = st.Close() }()
		_, _ = io.ReadAll(st)
	}
	// Both sessions should drain back to ~0 open streams.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cs.NumStreams() == 0 && ss.NumStreams() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("streams leaked: client=%d server=%d", cs.NumStreams(), ss.NumStreams())
}

func TestSessionCloseUnblocksReaders(t *testing.T) {
	cs, ss := pair()
	defer ss.Close()
	st, err := cs.OpenStream(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := st.Read(make([]byte, 16))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cs.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error after session close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader was not unblocked by Close")
	}
}
