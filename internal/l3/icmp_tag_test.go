//go:build linux

package l3

import (
	"bytes"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// A listener's kernel answers echo requests on its own, and its reply repeats
// our payload verbatim with the same ICMP id — by address and id alone it is
// indistinguishable from a real reply from the peer. A dialer that accepts one
// reads its own ciphertext as peer traffic, and the link carries nothing until
// it times out and cycles. The direction tag is what separates them.
func TestDialerRejectsItsOwnMirroredRequest(t *testing.T) {
	frame := []byte("encrypted frame")

	// What the dialer put on the wire: direction tag, tunnel port, frame.
	sent := append(appendTag(nil, tagToListener, 1194), frame...)
	req := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: 4242, Seq: 1, Data: sent}}
	raw, err := req.Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}

	// The kernel mirrors it back as an Echo Reply, same id, same payload. It
	// parses as a reply for us, so only the tag can reject it.
	mirrored := raw
	mirrored[0] = byte(ipv4.ICMPTypeEchoReply)
	mirrored[2], mirrored[3] = 0, 0 // checksum is not verified on parse
	data, ok := parseEcho(protoFor("icmp"), mirrored, 4242, true)
	if !ok {
		t.Fatal("mirrored reply did not parse as a reply; the test no longer exercises the case")
	}
	if _, ok := stripTag(data, tagToDialer, 1194); ok {
		t.Fatal("dialer accepted its own request mirrored back — the link will carry no traffic and cycle")
	}

	// A genuine reply from the peer is accepted, with the tag removed.
	good := append(appendTag(nil, tagToDialer, 1194), frame...)
	if got, ok := stripTag(good, tagToDialer, 1194); !ok || !bytes.Equal(got, frame) {
		t.Fatalf("genuine reply rejected or mistrimmed: %q ok=%v", got, ok)
	}
}

// The listener must ignore ordinary ping traffic. Without the tag every ping
// from anywhere opens a flow and is offered to the handshake.
func TestListenerIgnoresOrdinaryPing(t *testing.T) {
	if _, ok := stripTag([]byte("abcdefgh"), tagToListener, 1194); ok {
		t.Fatal("a plain ping payload was accepted as a tunnel frame")
	}
	if _, ok := stripTag(nil, tagToListener, 1194); ok {
		t.Fatal("an empty payload was accepted as a tunnel frame")
	}
	if _, ok := stripTag([]byte{tagToDialer}, tagToListener, 1194); ok {
		t.Fatal("a reply-tagged payload was accepted by the listener")
	}
	// And a correctly tagged frame belonging to a different tunnel on this host.
	other := append(appendTag(nil, tagToListener, 5555), []byte("their frame")...)
	if _, ok := stripTag(other, tagToListener, 1194); ok {
		t.Fatal("a frame from another tunnel on this host was accepted as ours")
	}
}
