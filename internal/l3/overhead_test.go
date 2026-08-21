package l3

import (
	"testing"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/crypto"
)

// What a tunnel costs in bytes is a question with a right answer, and it is one
// people pay for: a server billed by the terabyte carries every byte of
// encapsulation on the invoice. These numbers are quoted in the configuration
// docs and in the changelog, so they are asserted here — a change that makes
// frames bigger should have to update the figure it is quoted as, deliberately.
//
// Per inner packet on the ICMP carrier:
//
//	IPv4 header      20   (the kernel's, on a raw socket)
//	ICMP echo header  8   type, code, checksum, id, seq
//	tunnel tag        3   direction + tunnel port
//	AEAD             24   8-byte counter + 16-byte tag
//	record length     2   uint16 before each packet in a frame
//	                ───
//	                 57
func TestPerPacketOverheadIsWhatWeSayItIs(t *testing.T) {
	const (
		ipv4Header = 20
		want       = 57
	)
	got := ipv4Header + icmpEchoHdr + icmpFrameHdr + crypto.DatagramOverhead + 2
	if got != want {
		t.Fatalf("per-packet overhead is %d bytes, documented as %d — "+
			"update the figure in config.DupThreshold and the changelog, or undo the change",
			got, want)
	}

	// And what that means for the two cases that matter, so the percentages
	// quoted alongside cannot drift either.
	full := 1320 + got  // a full-size inner packet
	ack := 40 + got     // a pure TCP ACK
	if pct := float64(got) / float64(full) * 100; pct > 4.5 {
		t.Errorf("full-size packet overhead is %.1f%%, documented as ~4.3%%", pct)
	}
	if ack != 97 {
		t.Errorf("a pure ACK is %d bytes on the wire, documented as 97", ack)
	}
}

// Duplication has to be switchable, because it is the one cost here that buys
// something on a lossy path and buys nothing on a clean one — and the person
// paying for the terabytes is the one who knows which they have.
func TestDuplicationCanBeTurnedOff(t *testing.T) {
	t.Cleanup(func() { SetDupThreshold(dupThreshold) })

	for _, tc := range []struct {
		name  string
		cfg   config.Config
		frame int
		want  bool
	}{
		// The zero value must be the behaviour every existing tunnel has, or
		// every Config{} literal in the codebase quietly changes the data plane.
		{"unset duplicates a small frame", config.Config{}, 40, true},
		{"unset leaves a full frame alone", config.Config{}, 1300, false},
		{"negative turns it off", config.Config{DupThreshold: -1}, 40, false},
		{"negative, not even the smallest", config.Config{DupThreshold: -1}, 1, false},
		{"an explicit width is honoured", config.Config{DupThreshold: 64}, 40, true},
		{"and excludes what is above it", config.Config{DupThreshold: 64}, 100, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			SetDupThreshold(tc.cfg.DupBytes())
			w := int(dupUnderBytes.Load())
			got := w > 0 && tc.frame <= w
			if got != tc.want {
				t.Fatalf("frame of %d bytes duplicated = %v, want %v (threshold %d)",
					tc.frame, got, tc.want, w)
			}
		})
	}
}
