package mux

import (
	"net"
	"testing"
	"time"
)

// TestOpenStreamPriorityPropagates verifies that opening a stream high-priority
// (the @ll low-latency forward) marks the SYN flagPri, and the accepting side
// rebuilds the stream as high-priority too — so both directions get prioritized.
func TestOpenStreamPriorityPropagates(t *testing.T) {
	c1, c2 := net.Pipe()
	cs := Client(c1, Config{})
	ss := Server(c2, Config{})
	defer cs.Close()
	defer ss.Close()

	for _, hi := range []bool{true, false} {
		if _, err := cs.OpenStream([]byte{0, 1}, hi); err != nil {
			t.Fatalf("hi=%v OpenStream: %v", hi, err)
		}
		accepted := make(chan *Stream, 1)
		go func() {
			st, err := ss.AcceptStream()
			if err == nil {
				accepted <- st
			}
		}()
		select {
		case st := <-accepted:
			if st.hi != hi {
				t.Fatalf("accepted stream hi=%v, want %v (priority did not propagate)", st.hi, hi)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("server did not accept the stream")
		}
	}
}

// TestDeliverResetsOnOverflow verifies the receive-buffer ceiling: a peer that
// floods past maxRecvBuffer (ignoring flow control) gets the stream reset rather
// than growing memory without bound.
func TestDeliverResetsOnOverflow(t *testing.T) {
	c1, _ := net.Pipe()
	cs := Client(c1, Config{})
	defer cs.Close()

	st, err := cs.OpenStream([]byte{0, 1}, false)
	if err != nil {
		t.Fatal(err)
	}
	// Flood past the ceiling in one delivery (a conformant sender never would).
	st.deliver(make([]byte, maxRecvBuffer+1))
	if e := st.readErr(); e != ErrStreamReset {
		t.Fatalf("overflow should reset the stream, got err=%v", e)
	}
	// And it should have been reaped from the session map.
	if got := cs.getStream(st.id); got != nil {
		t.Error("overflowed stream should be removed from the session")
	}
}
