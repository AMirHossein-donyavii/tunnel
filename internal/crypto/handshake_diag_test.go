package crypto

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// A tunnel that never comes up leaves exactly one line in the log, and that line
// has to be enough to fix it. "not an emergency-tunnel peer" is the same
// sentence whether the other server is a version behind, is set to a different
// transport, or is a scanner off the internet — three problems with three
// different fixes and no way to tell them apart.
//
// Each of these is a real thing an operator hits; the message must name it.
func TestRejectedHandshakeSaysWhatIsWrong(t *testing.T) {
	etHello := func(ver byte) []byte {
		b := make([]byte, 4+1+pubLen)
		binary.BigEndian.PutUint32(b, 0x45540200|uint32(ver))
		b[4] = ver
		return b
	}
	pad := func(b []byte) []byte {
		out := make([]byte, 4+1+pubLen)
		copy(out, b)
		return out
	}

	for _, tc := range []struct {
		name  string
		hello []byte
		want  string // a phrase that has to appear
	}{
		{"an older core", etHello(protoVer - 1), "different version"},
		{"a newer core", etHello(protoVer + 1), "different version"},
		{"a TLS transport against a plain port", pad([]byte{0x16, 0x03, 0x01, 0x02, 0x00}), "different transports"},
		{"a ws/wss transport against a plain port", pad([]byte("GET /chat HTTP/1.1")), "ws/wss"},
		{"something else entirely", pad([]byte{0x00, 0x01, 0x02, 0x03, 0x04}), "not an emergency-tunnel peer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := describeHello(tc.hello)
			if err == nil {
				t.Fatal("accepted a hello that is not ours")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the log would say %q, which does not tell the operator about %q", err, tc.want)
			}
		})
	}
}

// The version report has to name the peer's version, not ours, or it points at
// the wrong server.
func TestVersionMismatchNamesBothVersions(t *testing.T) {
	b := make([]byte, 4+1+pubLen)
	binary.BigEndian.PutUint32(b, 0x45540202)
	b[4] = 2
	got := describeHello(b).Error()
	if !strings.Contains(got, "v2") || !strings.Contains(got, "v3") {
		t.Fatalf("message %q must name both the peer's protocol version and ours", got)
	}
}

// The diagnosis runs on the accepting side of a real connection, so a peer that
// speaks the wrong thing must be rejected there rather than hanging or being
// let through.
func TestServerHandshakeRejectsATLSPeer(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	go func() {
		hello := make([]byte, 4+1+pubLen)
		hello[0], hello[1], hello[2] = 0x16, 0x03, 0x01
		_, _ = a.Write(hello)
	}()

	_, err := ServerHandshake(b, "aes-256-gcm")
	if err == nil {
		t.Fatal("a TLS client was accepted as a tunnel peer")
	}
	if !strings.Contains(err.Error(), "transport") {
		t.Fatalf("got %q, want a message naming the transport mismatch", err)
	}
}
