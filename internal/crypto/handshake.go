package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Handshake (ephemeral X25519 — no pre-shared key):
//
//	client -> server:  magic(4) ver(1) clientPub(32)
//	server -> client:  serverPub(32)
//
// Both sides compute shared = X25519(ownPriv, peerPub) and derive per-direction
// AEAD keys via HKDF(shared, salt = clientPub|serverPub). Keys are fresh per
// connection (forward secrecy) and nothing needs to be pre-shared.
//
// Security note: this provides confidentiality but NOT peer authentication — any
// party that can reach the tunnel port can complete the exchange. Restrict the
// tunnel port to the peer's IP with a firewall (see docs). This matches the
// project's primary threat model (defeat passive DPI / censorship).
const (
	// magic/protoVer identify the wire protocol. v3 changed the framing: a frame
	// is written with a single syscall, frames may carry up to MaxPlaintext
	// bytes, and the L3 engine maps one packet batch onto one AEAD frame instead
	// of adding a second length header. A v2 peer therefore cannot talk to a v3
	// peer — both servers must run the same core version. The mismatch surfaces
	// here as a clean handshake rejection rather than as corrupt data later.
	magic       = 0x45540203 // "ET" protocol v3 (ephemeral ECDH, single-syscall framing)
	protoVer    = 3
	pubLen      = 32
	handshakeTO = 10 * time.Second
)

var (
	labelC2SKey = []byte("emergency-tunnel c2s key")
	labelS2CKey = []byte("emergency-tunnel s2c key")
	errBadMagic = fmt.Errorf("handshake: not an emergency-tunnel peer (bad magic/version)")
	errECDH     = fmt.Errorf("handshake: invalid key share")
)

func deriveKey(shared, cpub, spub, label []byte) []byte {
	salt := make([]byte, 0, len(cpub)+len(spub))
	salt = append(salt, cpub...)
	salt = append(salt, spub...)
	r := hkdf.New(sha256.New, shared, salt, label)
	key := make([]byte, 32)
	_, _ = io.ReadFull(r, key)
	return key
}

// describeHello turns a rejected client hello into something the operator can
// act on.
//
// "not an emergency-tunnel peer" is true but useless: it is the same line
// whether the other server is a version behind, is configured with a different
// transport, or is not the other server at all but a scanner off the internet —
// and those have completely different fixes. The first bytes distinguish them,
// so say which one it is.
func describeHello(hello []byte) error {
	switch {
	// Our own signature with a different version byte: the two servers are
	// running different core builds and the wire format changed between them.
	case hello[0] == 'E' && hello[1] == 'T':
		return fmt.Errorf("handshake: peer is an emergency-tunnel of a different version "+
			"(it speaks protocol v%d, this core speaks v%d) — update both servers to the same release",
			hello[4], protoVer)

	// A TLS record: content type 22 (handshake), version 3.x. This is what a
	// peer configured for the stealth/wss/tls transports sends, and it reaches a
	// plain-tcp listener only when the two sides disagree about the transport.
	case hello[0] == 0x16 && hello[1] == 0x03:
		return fmt.Errorf("handshake: peer opened with TLS on a plain tunnel port — " +
			"the two sides are set to different transports; make transport match on both servers")

	// An HTTP request line: either a wss/ws peer against a non-WebSocket
	// listener, or a probe.
	case looksHTTP(hello):
		return fmt.Errorf("handshake: peer sent an HTTP request, not a tunnel handshake — " +
			"if this is your other server, its transport is set to ws/wss while this one is not")

	// Anything else. Two very different things land here and the bytes cannot
	// separate them, because one of them is deliberately shapeless: the stealth
	// transport opens with 48 uniformly random bytes precisely so that a port
	// scan finds nothing to fingerprint. A peer configured for it, dialing a
	// plain-tcp listener, is therefore indistinguishable by content from a bot
	// probing the port. Print the opening bytes so the two can at least be told
	// apart by eye — a scanner repeats a recognisable string, a stealth peer
	// never sends the same bytes twice.
	default:
		return fmt.Errorf("%w — opens with %s; if this is your other server its transport "+
			"does not match this one (stealth and the other obfuscated carriers open with "+
			"random bytes), otherwise it is unrelated traffic probing this port",
			errBadMagic, hexPreview(hello[:8]))
	}
}

func hexPreview(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*3)
	for i, c := range b {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

func looksHTTP(b []byte) bool {
	for _, m := range [...]string{"GET ", "POST", "HEAD", "PUT ", "OPTI", "CONN"} {
		if len(b) >= len(m) && string(b[:len(m)]) == m {
			return true
		}
	}
	return false
}

// ClientHandshake performs the ephemeral X25519 exchange (dialing side) and
// returns an encrypted SecureConn.
func ClientHandshake(conn net.Conn, cipherName string) (*SecureConn, error) {
	_ = conn.SetDeadline(time.Now().Add(handshakeTO))
	defer conn.SetDeadline(time.Time{})

	var cpriv [32]byte
	if _, err := rand.Read(cpriv[:]); err != nil {
		return nil, err
	}
	cpub, err := curve25519.X25519(cpriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	hello := make([]byte, 4+1+pubLen)
	binary.BigEndian.PutUint32(hello, magic)
	hello[4] = protoVer
	copy(hello[5:], cpub)
	if _, err := conn.Write(hello); err != nil {
		return nil, err
	}

	spub := make([]byte, pubLen)
	if _, err := io.ReadFull(conn, spub); err != nil {
		return nil, fmt.Errorf("handshake: reading server key: %w", err)
	}
	shared, err := curve25519.X25519(cpriv[:], spub)
	if err != nil {
		return nil, errECDH
	}
	c2s := deriveKey(shared, cpub, spub, labelC2SKey)
	s2c := deriveKey(shared, cpub, spub, labelS2CKey)
	return wrap(conn, cipherName, c2s, s2c) // client: send c2s, receive s2c
}

// ServerHandshake is the accepting side of the ephemeral X25519 exchange.
func ServerHandshake(conn net.Conn, cipherName string) (*SecureConn, error) {
	_ = conn.SetDeadline(time.Now().Add(handshakeTO))
	defer conn.SetDeadline(time.Time{})

	hello := make([]byte, 4+1+pubLen)
	if _, err := io.ReadFull(conn, hello); err != nil {
		return nil, fmt.Errorf("handshake: reading client hello: %w", err)
	}
	if binary.BigEndian.Uint32(hello) != magic || hello[4] != protoVer {
		return nil, describeHello(hello)
	}
	cpub := hello[5 : 5+pubLen]

	var spriv [32]byte
	if _, err := rand.Read(spriv[:]); err != nil {
		return nil, err
	}
	spub, err := curve25519.X25519(spriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(spub); err != nil {
		return nil, err
	}
	shared, err := curve25519.X25519(spriv[:], cpub)
	if err != nil {
		return nil, errECDH
	}
	c2s := deriveKey(shared, cpub, spub, labelC2SKey)
	s2c := deriveKey(shared, cpub, spub, labelS2CKey)
	return wrap(conn, cipherName, s2c, c2s) // server: send s2c, receive c2s
}
