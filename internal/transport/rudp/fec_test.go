package rudp

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

// send pushes packets through the encoder, drops the ones the caller says to
// drop, and returns everything the decoder handed up.
func send(t *testing.T, p FECParams, pkts [][]byte, drop func(i int) bool) [][]byte {
	t.Helper()
	enc, err := newFECEncoder(p)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := newFECDecoder(p)
	if err != nil {
		t.Fatal(err)
	}
	var got [][]byte
	wire := 0
	for _, pkt := range pkts {
		for _, out := range enc.encode(pkt) {
			i := wire
			wire++
			if drop(i) {
				continue
			}
			got = append(got, dec.decode(out)...)
		}
	}
	return got
}

func pkts(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		// Varying lengths on purpose: shards are padded to the longest in the
		// group, and a recovered short packet must come back its own length.
		// All are above fecMinCoded, so they take the coded path rather than
		// the bypass one.
		out[i] = []byte(fmt.Sprintf("packet-%03d%s", i,
			bytes.Repeat([]byte("x"), fecMinCoded+i%40)))
	}
	return out
}

func contains(hay [][]byte, needle []byte) bool {
	for _, h := range hay {
		if bytes.Equal(h, needle) {
			return true
		}
	}
	return false
}

// Nothing lost: every packet arrives once, unchanged, and no round trip was
// spent on any of them.
func TestFECCleanPathDeliversEverything(t *testing.T) {
	p := FECParams{Data: 10, Parity: 3}
	in := pkts(30)
	got := send(t, p, in, func(int) bool { return false })
	for _, want := range in {
		if !contains(got, want) {
			t.Fatalf("packet %q never arrived", want)
		}
	}
}

// The case FEC exists for: an isolated loss is repaired from packets already in
// flight, so the receiver never has to ask for it.
func TestFECRecoversLossWithoutRetransmission(t *testing.T) {
	p := FECParams{Data: 10, Parity: 3}
	in := pkts(30)
	// Drop one packet in each group of 13 on the wire.
	got := send(t, p, in, func(i int) bool { return i%13 == 4 })
	for _, want := range in {
		if !contains(got, want) {
			t.Fatalf("packet %q was lost and not recovered", want)
		}
	}
}

// Up to parityShards losses in a group are all recoverable. The packet count is
// a whole number of groups on purpose: a partly-filled group carries no parity
// yet, so its packets are not protected until it completes (see fecEncoder).
func TestFECRecoversUpToParityLosses(t *testing.T) {
	p := FECParams{Data: 10, Parity: 3}
	in := pkts(30)
	got := send(t, p, in, func(i int) bool { m := i % 13; return m == 1 || m == 5 || m == 9 })
	for _, want := range in {
		if !contains(got, want) {
			t.Fatalf("packet %q not recovered from 3 losses in its group", want)
		}
	}
}

// Beyond the code's capacity, FEC must degrade rather than corrupt: whatever
// arrives is intact, and the ARQ above is left to retransmit the rest.
func TestFECBeyondCapacityDeliversOnlyIntactPackets(t *testing.T) {
	p := FECParams{Data: 10, Parity: 2}
	in := pkts(24)
	got := send(t, p, in, func(i int) bool { m := i % 12; return m < 5 })
	for _, g := range got {
		if !contains(in, g) {
			t.Fatalf("decoder produced a packet that was never sent: %q", g)
		}
	}
}

// Random loss across a long run, at a rate a bad route really shows.
func TestFECUnderRandomLoss(t *testing.T) {
	p := FECParams{Data: 10, Parity: 3}
	in := pkts(500)
	rng := rand.New(rand.NewSource(7))
	got := send(t, p, in, func(int) bool { return rng.Float64() < 0.05 })

	recovered := 0
	for _, want := range in {
		if contains(got, want) {
			recovered++
		}
	}
	// With 5% loss and a 10:3 code, nearly everything should come through; the
	// ARQ handles the remainder. Assert on the shape, not an exact count.
	if recovered < len(in)*95/100 {
		t.Fatalf("only %d/%d packets survived 5%% loss — FEC is not doing its job", recovered, len(in))
	}
	for _, g := range got {
		if !contains(in, g) {
			t.Fatalf("decoder produced a packet that was never sent: %q", g)
		}
	}
}

// The decoder is exposed to whatever the internet sends at an open UDP port.
func TestFECDecoderIgnoresJunk(t *testing.T) {
	dec, err := newFECDecoder(FECParams{Data: 10, Parity: 3})
	if err != nil {
		t.Fatal(err)
	}
	for _, junk := range [][]byte{
		nil,
		{1},
		{1, 2, 3, 4, 5},                         // shorter than the header
		{0, 0, 0, 0, 0xAA, 0xBB},                // unknown type
		{0, 0, 0, 0, 0xF1, 0xF1},                // data type, no body
		{0, 0, 0, 0, 0xF1, 0xF1, 0xFF, 0xFF, 1}, // length beyond the shard
		{0, 0, 0, 0, 0xF1, 0xF1, 0, 0},          // zero-length payload
	} {
		if out := dec.decode(junk); len(out) != 0 {
			t.Fatalf("junk %v produced %d packets", junk, len(out))
		}
	}
}

// Disabled parameters must build nothing at all, so the packet path stays
// byte-identical to a tunnel without FEC.
func TestFECDisabledBuildsNoCodec(t *testing.T) {
	for _, p := range []FECParams{{}, {Data: 10}, {Parity: 3}} {
		e, err := newFECEncoder(p)
		if err != nil || e != nil {
			t.Fatalf("%+v built an encoder (%v)", p, err)
		}
		d, err := newFECDecoder(p)
		if err != nil || d != nil {
			t.Fatalf("%+v built a decoder (%v)", p, err)
		}
		if p.Enabled() {
			t.Fatalf("%+v reports enabled", p)
		}
	}
}

// A segment too small to be worth coding still has to arrive, and must not
// disturb the group arithmetic of the packets around it.
func TestFECBypassesSmallSegmentsWithoutBreakingGroups(t *testing.T) {
	p := FECParams{Data: 10, Parity: 3}
	enc, _ := newFECEncoder(p)
	dec, _ := newFECDecoder(p)

	ack := []byte("tiny-ack")
	big := pkts(20)

	var got [][]byte
	wire := 0
	for i, pkt := range big {
		// An acknowledgement between every pair of data packets, as the ARQ
		// really interleaves them.
		for _, out := range enc.encode(ack) {
			got = append(got, dec.decode(out)...)
		}
		for _, out := range enc.encode(pkt) {
			w := wire
			wire++
			if w%13 == 6 && i < 10 { // lose one data packet in the first group
				continue
			}
			got = append(got, dec.decode(out)...)
		}
	}
	for _, want := range big {
		if !contains(got, want) {
			t.Fatalf("packet %q lost — a bypassed segment broke the group arithmetic", want[:20])
		}
	}
	if !contains(got, ack) {
		t.Fatal("the bypassed acknowledgement never arrived")
	}
}
