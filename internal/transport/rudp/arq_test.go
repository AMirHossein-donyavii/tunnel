package rudp

import (
	"bytes"
	"math/rand"
	"testing"
)

// pipe wires two ARQs together with a controllable loss/reorder model, so the
// state machine can be driven deterministically without sockets.
type pipe struct {
	a, b       *ARQ
	loss       float64
	rng        *rand.Rand
	inFlightAB [][]byte
	inFlightBA [][]byte
}

func newPipe(loss float64, seed int64) *pipe {
	p := &pipe{loss: loss, rng: rand.New(rand.NewSource(seed))}
	p.a = newARQ(7, func(b []byte) { p.queue(&p.inFlightAB, b) })
	p.b = newARQ(7, func(b []byte) { p.queue(&p.inFlightBA, b) })
	return p
}

func (p *pipe) queue(q *[][]byte, b []byte) {
	if p.rng.Float64() < p.loss {
		return // dropped in transit
	}
	*q = append(*q, append([]byte(nil), b...))
}

// step advances both endpoints by one flush interval and delivers whatever is
// in flight.
func (p *pipe) step(now uint32) {
	p.a.Update(now)
	p.b.Update(now)
	ab, ba := p.inFlightAB, p.inFlightBA
	p.inFlightAB, p.inFlightBA = nil, nil
	for _, d := range ab {
		p.b.Input(d)
	}
	for _, d := range ba {
		p.a.Input(d)
	}
}

// transfer sends payload from a to b, returning what arrived.
func (p *pipe) transfer(t *testing.T, payload []byte, maxSteps int) []byte {
	t.Helper()
	p.a.Send(payload)
	var got []byte
	buf := make([]byte, 64*1024)
	for i := 0; i < maxSteps && len(got) < len(payload); i++ {
		p.step(uint32(i * 10))
		if n := p.b.Recv(buf); n > 0 {
			got = append(got, buf[:n]...)
		}
	}
	return got
}

func TestARQDeliversInOrder(t *testing.T) {
	p := newPipe(0, 1)
	payload := make([]byte, 200*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	got := p.transfer(t, payload, 4000)
	if !bytes.Equal(got, payload) {
		t.Fatalf("delivered %d of %d bytes, content match=%v", len(got), len(payload), bytes.Equal(got, payload))
	}
}

// The point of the whole package: bytes must arrive complete and in order even
// when the path drops a substantial fraction of datagrams.
func TestARQRecoversFromLoss(t *testing.T) {
	for _, loss := range []float64{0.05, 0.15, 0.30} {
		p := newPipe(loss, 42)
		payload := make([]byte, 64*1024)
		for i := range payload {
			payload[i] = byte(i * 7)
		}
		got := p.transfer(t, payload, 20000)
		if !bytes.Equal(got, payload) {
			t.Fatalf("loss=%.0f%%: delivered %d of %d bytes", loss*100, len(got), len(payload))
		}
	}
}

// Congestion control must actually open the window rather than crawling one
// segment at a time forever.
func TestARQCongestionWindowOpens(t *testing.T) {
	p := newPipe(0, 3)
	p.a.Send(make([]byte, 512*1024))
	for i := 0; i < 600; i++ {
		p.step(uint32(i * 10))
		buf := make([]byte, 64*1024)
		p.b.Recv(buf)
	}
	cwnd, _, _, _, _ := p.a.Stats()
	if cwnd < 8 {
		t.Errorf("cwnd stayed at %d — congestion control is not opening the window", cwnd)
	}
}

// Flow control: a receiver that never reads must stop the sender rather than
// letting it push unboundedly.
func TestARQRespectsPeerWindow(t *testing.T) {
	p := newPipe(0, 4)
	p.b.SetWindow(0, 8) // tiny receive window, and b never calls Recv
	p.a.Send(make([]byte, 512*1024))
	for i := 0; i < 300; i++ {
		p.step(uint32(i * 10))
	}
	_, inflight, _, _, _ := p.a.Stats()
	if inflight > 64 {
		t.Errorf("%d segments in flight against an 8-segment peer window", inflight)
	}
}

// A path that goes away entirely must be reported dead rather than retrying
// forever.
func TestARQDetectsDeadPath(t *testing.T) {
	p := newPipe(1.0, 5) // every datagram dropped
	p.a.Send([]byte("hello"))
	for i := 0; i < 4000 && !p.a.Dead(); i++ {
		p.step(uint32(i * 50))
	}
	if !p.a.Dead() {
		t.Fatal("a totally black-holed path was never reported dead")
	}
}

func TestARQRTTEstimation(t *testing.T) {
	p := newPipe(0, 6)
	p.transfer(t, make([]byte, 32*1024), 2000)
	_, _, _, srtt, rto := p.a.Stats()
	if rto < rtoMin || rto > rtoMax {
		t.Errorf("rto %d out of bounds [%d,%d]", rto, rtoMin, rtoMax)
	}
	_ = srtt
}

func TestSegmentEncodeRoundTrip(t *testing.T) {
	s := &segment{conv: 0xdeadbeef, cmd: cmdPush, wnd: 1234, ts: 99, sn: 7, una: 3, data: []byte("payload")}
	b := make([]byte, hdrLen+len(s.data))
	if n := s.encode(b); n != hdrLen+7 {
		t.Fatalf("encoded %d bytes", n)
	}
	a := newARQ(0xdeadbeef, func([]byte) {})
	if !a.Input(b) {
		t.Fatal("a well-formed segment was rejected")
	}
	if a.rcvNxt != 0 {
		t.Errorf("sn 7 with rcvNxt 0 should have been buffered, not delivered")
	}
}

// A datagram for a different connection must be ignored, not mixed in.
func TestARQRejectsForeignConv(t *testing.T) {
	s := &segment{conv: 1, cmd: cmdPush, data: []byte("x")}
	b := make([]byte, hdrLen+1)
	s.encode(b)
	a := newARQ(2, func([]byte) {})
	if a.Input(b) {
		t.Fatal("accepted a segment from a different conversation")
	}
}
