package mux

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// ---- writeQueue unit tests --------------------------------------------------

func dataFrame(id uint32, n int) outFrame {
	return outFrame{typ: frameData, id: id, data: make([]byte, n)}
}

func TestWriteQueueControlGoesFirst(t *testing.T) {
	q := newWriteQueue()
	q.tryPutData(dataFrame(1, 100), false)
	q.tryPutData(dataFrame(1, 100), false)
	q.putCtrl(outFrame{typ: frameWinUp, id: 7, ctl: 42})

	f, ok := q.take()
	if !ok || f.typ != frameWinUp {
		t.Fatalf("expected the control frame first, got typ=%d ok=%v", f.typ, ok)
	}
}

// A WINDOW_UPDATE stuck behind bulk data stalls the peer's sender, so the
// rotation must never let one stream's backlog monopolise the writer.
func TestWriteQueueRoundRobinsStreams(t *testing.T) {
	q := newWriteQueue()
	// Stream 1 queues a long backlog first; stream 3 arrives afterwards.
	for i := 0; i < 10; i++ {
		q.tryPutData(dataFrame(1, 100), false)
	}
	q.tryPutData(dataFrame(3, 100), false)

	var order []uint32
	for i := 0; i < 4; i++ {
		f, ok := q.take()
		if !ok {
			break
		}
		order = append(order, f.id)
	}
	// Strict FIFO would give 1,1,1,1 and stream 3 would wait out the backlog.
	found3 := false
	for _, id := range order[:2] {
		if id == 3 {
			found3 = true
		}
	}
	if !found3 {
		t.Fatalf("stream 3 was starved behind stream 1's backlog: order=%v", order)
	}
}

func TestWriteQueueHighPriorityStreamsFirst(t *testing.T) {
	q := newWriteQueue()
	q.tryPutData(dataFrame(1, 100), false) // bulk
	q.tryPutData(dataFrame(5, 100), true)  // low-latency stream

	f, ok := q.take()
	if !ok || f.id != 5 {
		t.Fatalf("expected the high-priority stream first, got id=%d ok=%v", f.id, ok)
	}
}

func TestWriteQueueEnforcesByteBudget(t *testing.T) {
	q := newWriteQueue()
	accepted := 0
	for i := 0; i < 1000; i++ {
		ok, closed := q.tryPutData(dataFrame(1, maxFrame), false)
		if closed {
			t.Fatal("queue closed unexpectedly")
		}
		if !ok {
			break
		}
		accepted++
	}
	if accepted == 0 {
		t.Fatal("queue accepted nothing")
	}
	cur, _ := q.snapshot()
	if cur > maxQueuedBytes+maxFrame {
		t.Fatalf("queued %d bytes, budget is %d", cur, maxQueuedBytes)
	}
	// Draining must free the budget again.
	for {
		if _, ok := q.take(); !ok {
			break
		}
	}
	if cur, _ := q.snapshot(); cur != 0 {
		t.Fatalf("byte accounting leaked: %d bytes still counted", cur)
	}
}

// A payload-free frame (FIN) must always be admitted: it costs no bytes and
// blocking it behind a full queue would stall stream teardown.
func TestWriteQueueAlwaysAdmitsEmptyFrames(t *testing.T) {
	q := newWriteQueue()
	for {
		ok, _ := q.tryPutData(dataFrame(1, maxFrame), false)
		if !ok {
			break
		}
	}
	if ok, closed := q.tryPutData(outFrame{typ: frameFIN, id: 1}, false); !ok || closed {
		t.Fatal("FIN was refused by a full queue")
	}
}

func TestWriteQueueDropFreesBudget(t *testing.T) {
	q := newWriteQueue()
	for i := 0; i < 4; i++ {
		q.tryPutData(dataFrame(1, maxFrame), false)
		q.tryPutData(dataFrame(2, maxFrame), false)
	}
	before, _ := q.snapshot()
	q.drop(1)
	after, _ := q.snapshot()
	if after >= before {
		t.Fatalf("drop did not release stream 1's bytes: %d -> %d", before, after)
	}
	// Nothing from stream 1 may still be served.
	for {
		f, ok := q.take()
		if !ok {
			break
		}
		if f.id == 1 {
			t.Fatal("a dropped stream's frame was still served")
		}
	}
}

func TestFrameRingWrapAround(t *testing.T) {
	var r frameRing
	for round := 0; round < 5; round++ {
		for i := 0; i < 10; i++ {
			r.push(outFrame{id: uint32(i)})
		}
		for i := 0; i < 10; i++ {
			f, ok := r.pop()
			if !ok || f.id != uint32(i) {
				t.Fatalf("round %d: got id=%d ok=%v, want %d", round, f.id, ok, i)
			}
		}
		if _, ok := r.pop(); ok {
			t.Fatal("pop succeeded on an empty ring")
		}
	}
}

// ---- end-to-end guards ------------------------------------------------------

func sessionPair(t *testing.T, cfg Config) (*Session, *Session) {
	t.Helper()
	c1, c2 := net.Pipe()
	cs, ss := Client(c1, cfg), Server(c2, cfg)
	t.Cleanup(func() { cs.Close(); ss.Close() })
	return cs, ss
}

// FIN travels on the same per-stream queue as DATA. If it were routed through
// the control class it would overtake the stream's buffered data and the
// receiver would see EOF early — silently truncating every transfer that closed
// promptly after writing.
func TestCloseDoesNotTruncateBufferedData(t *testing.T) {
	cs, ss := sessionPair(t, Config{AcceptBacklog: 4, Window: 1 << 20})

	payload := bytes.Repeat([]byte("emergency-tunnel"), 64*1024) // 1 MiB
	got := make(chan []byte, 1)
	go func() {
		st, err := ss.AcceptStream()
		if err != nil {
			got <- nil
			return
		}
		b, _ := io.ReadAll(st)
		got <- b
	}()

	st, err := cs.OpenStream(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = st.Write(payload)
		_ = st.Close() // immediately after the last write
	}()

	select {
	case b := <-got:
		if len(b) != len(payload) {
			t.Fatalf("received %d of %d bytes — FIN overtook queued data", len(b), len(payload))
		}
		if !bytes.Equal(b, payload) {
			t.Fatal("payload corrupted in transit")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("transfer did not complete")
	}
}

// A bulk transfer must not be able to stall an interactive stream sharing the
// session. Before the per-stream rotation, the interactive stream's frames sat
// behind the bulk stream's entire backlog.
func TestBulkStreamDoesNotStarveInteractive(t *testing.T) {
	cfg := Config{AcceptBacklog: 8, Window: 1 << 20}
	cs, ss := sessionPair(t, cfg)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			st, err := ss.AcceptStream()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, st) }()
		}
	}()

	// Saturate the session with a bulk stream.
	bulk, err := cs.OpenStream(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	stopBulk := make(chan struct{})
	go func() {
		chunk := make([]byte, maxFrame)
		for {
			select {
			case <-stopBulk:
				return
			default:
			}
			if _, err := bulk.Write(chunk); err != nil {
				return
			}
		}
	}()
	defer close(stopBulk)
	time.Sleep(200 * time.Millisecond) // let the backlog build

	// An interactive stream opened mid-transfer must get served promptly.
	inter, err := cs.OpenStream(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := inter.Write([]byte("ping"))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("interactive write failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("interactive stream was starved by the bulk transfer")
	}
}

// Window-update credit is the one thing that must never be lost: the peer's
// sender waits on it, and a dropped update strands that stream forever. It is
// therefore accumulated rather than queued as individual frames.
func TestWindowUpdatesAreLosslessAndCoalesced(t *testing.T) {
	q := newWriteQueue()
	// Far more updates than any frame backlog could hold.
	const n = ctrlBacklog * 4
	var want uint32
	for i := 0; i < n; i++ {
		q.putWinUp(9, 100)
		want += 100
	}
	// Fill the control class too, so a naive implementation would be dropping.
	for i := 0; i < ctrlBacklog*2; i++ {
		q.putCtrl(outFrame{typ: framePing, id: uint32(i)})
	}

	var got uint32
	for {
		f, ok := q.take()
		if !ok {
			break
		}
		if f.typ == frameWinUp && f.id == 9 {
			got += f.ctl
		}
	}
	if got != want {
		t.Fatalf("credit delivered = %d, queued = %d — %d bytes of window were lost",
			got, want, want-got)
	}
}

// Credit for different streams must stay separate.
func TestWindowUpdatesPerStream(t *testing.T) {
	q := newWriteQueue()
	q.putWinUp(1, 10)
	q.putWinUp(2, 20)
	q.putWinUp(1, 5)

	got := map[uint32]uint32{}
	for {
		f, ok := q.take()
		if !ok {
			break
		}
		if f.typ == frameWinUp {
			got[f.id] += f.ctl
		}
	}
	if got[1] != 15 || got[2] != 20 {
		t.Fatalf("credit misrouted: stream1=%d (want 15) stream2=%d (want 20)", got[1], got[2])
	}
}
