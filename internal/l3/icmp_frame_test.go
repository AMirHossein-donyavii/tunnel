//go:build linux

package l3

import (
	"bytes"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// The echo header is now written by hand (appendICMP) instead of through
// icmp.Message.Marshal, to keep an allocation off every packet. That is only
// safe if the bytes are identical to what the library produced — a wrong
// checksum or a shifted field would make the peer's kernel drop the packet and
// look exactly like path loss. This proves byte-for-byte equality against the
// library for both directions and both protocols.
//
// The frame header — direction tag then tunnel port — leads the payload in this
// carrier, so the library reference is built with that header prepended to the
// frame, matching what appendTagged lays down.
func TestFramingMatchesLibraryMarshal(t *testing.T) {
	frame := []byte("an encrypted datagram of some length \x00\x01\xfe\xff")

	cases := []struct {
		name  string
		proto icmpProto
		reply bool
		tag   byte
		// library message types for this direction
		typ icmp.Type
	}{
		{"v4-request", protoFor("icmp"), false, tagToListener, ipv4.ICMPTypeEcho},
		{"v4-reply", protoFor("icmp"), true, tagToDialer, ipv4.ICMPTypeEchoReply},
		{"v6-request", protoFor("bip"), false, tagToListener, ipv6.ICMPTypeEchoRequest},
		{"v6-reply", protoFor("bip"), true, tagToDialer, ipv6.ICMPTypeEchoReply},
	}

	const id, seq = 0x4242, 0x0abc
	const tunnelPort = 0x04d2 // 1234
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Reference: the library builds the whole message. For ICMPv6 the
			// checksum is left to the kernel's pseudo-header, so Marshal is
			// called with a nil psh and the two checksum bytes are zeroed to
			// match a raw-socket send (which is what appendICMP does).
			ref := icmp.Message{Type: tc.typ, Code: 0,
				Body: &icmp.Echo{ID: id, Seq: seq,
					Data: append([]byte{tc.tag, tunnelPort >> 8, tunnelPort & 0xff}, frame...)}}
			want, err := ref.Marshal(nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.proto.v6 {
				want[2], want[3] = 0, 0
			}

			var got []byte
			if tc.reply {
				got = appendReply(nil, tc.proto, id, seq, tc.tag, tunnelPort, frame)
			} else {
				got = appendEcho(nil, tc.proto, id, seq, tc.tag, tunnelPort, frame)
			}

			if !bytes.Equal(got, want) {
				t.Fatalf("hand-rolled framing differs from library Marshal\n got: % x\nwant: % x", got, want)
			}
		})
	}
}

// appendICMP reuses the caller's buffer; a second call after a reset must
// produce exactly the same bytes as a fresh one, or the reuse in Write/Read is
// corrupting state.
func TestFramingBufferReuseIsClean(t *testing.T) {
	p := protoFor("icmp")
	a := appendEcho(nil, p, 7, 1, tagToListener, 1194, []byte("first payload here"))

	buf := make([]byte, 0, 512)
	buf = appendEcho(buf[:0], p, 99, 42, tagToDialer, 1194, []byte("something else entirely, longer"))
	buf = appendEcho(buf[:0], p, 7, 1, tagToListener, 1194, []byte("first payload here"))

	if !bytes.Equal(a, buf) {
		t.Fatalf("reused buffer produced different bytes\n fresh: % x\nreused: % x", a, buf)
	}
}
