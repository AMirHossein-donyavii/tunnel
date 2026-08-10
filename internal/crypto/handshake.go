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
		return nil, errBadMagic
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
