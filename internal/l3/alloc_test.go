package l3

import (
	"net"
	"testing"
)

// These paths run once per packet, in both directions, for the whole life of a
// tunnel. An allocation here is not a style question: at line rate it is tens of
// thousands of allocations a second, and the collection they cause comes out of
// the CPU budget for moving bytes — on servers that are typically one core.
//
// Every one of these allocated at some point, and nothing failed when they did,
// because a correctness test cannot see an allocation. These assert the property
// directly so a future change to the framing has to keep it.

func TestSendPathDoesNotAllocate(t *testing.T) {
	payload := make([]byte, 1400) // a full-MTU frame, the common case
	src, dst := net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)

	cases := []struct {
		name string
		fn   func(buf []byte) []byte
	}{
		{"icmp-carrier-request", func(buf []byte) []byte {
			return appendEcho(buf[:0], icmpProto{v6: false}, 4242, 7, tagToListener, 1194, payload)
		}},
		{"icmp-carrier-reply", func(buf []byte) []byte {
			return appendReply(buf[:0], icmpProto{v6: false}, 4242, 7, tagToDialer, 1194, payload)
		}},
		{"bip-carrier-request", func(buf []byte) []byte {
			return appendEcho(buf[:0], icmpProto{v6: true}, 4242, 7, tagToListener, 1194, payload)
		}},
		{"spf-icmp-codec", func(buf []byte) []byte {
			return icmpCodec{}.encode(buf[:0], src, dst, 4242, 1234, 7, payload, false)
		}},
		{"spf-tcp-codec", func(buf []byte) []byte {
			return tcpCodec{}.encode(buf[:0], src, dst, 4242, 1234, 7, payload, false)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, 0, 2048) // the caller-owned buffer, as in the carriers
			var out []byte
			got := testing.AllocsPerRun(200, func() { out = tc.fn(buf) })
			if len(out) == 0 {
				t.Fatal("encoded nothing")
			}
			if got != 0 {
				t.Fatalf("%v allocations per packet sent; the send path must reuse the caller's buffer", got)
			}
		})
	}
}

// The receive path parses a header and looks up a flow. Both used to allocate:
// the parse built a message object, and the flow key was a formatted string.
func TestReceivePathDoesNotAllocate(t *testing.T) {
	buf := make([]byte, 0, 2048)
	msg := appendEcho(buf, icmpProto{v6: false}, 4242, 7, tagToListener, 1194, make([]byte, 1400))
	addr := &net.IPAddr{IP: net.IPv4(203, 0, 113, 9)}

	t.Run("parse", func(t *testing.T) {
		var ok bool
		got := testing.AllocsPerRun(200, func() {
			_, _, ok = parseEchoMsg(msg, false, false)
		})
		if !ok {
			t.Fatal("parse rejected a message this package built")
		}
		if got != 0 {
			t.Fatalf("%v allocations per packet received in the parse", got)
		}
	})

	t.Run("flow-key", func(t *testing.T) {
		var ok bool
		got := testing.AllocsPerRun(200, func() {
			_, ok = makeICMPKey(addr, 4242)
		})
		if !ok {
			t.Fatal("key construction failed for an ordinary IPv4 peer")
		}
		if got != 0 {
			t.Fatalf("%v allocations per packet received building the flow key", got)
		}
	})
}
