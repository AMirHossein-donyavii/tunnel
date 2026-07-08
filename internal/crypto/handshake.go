package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Wire handshake (all sizes in bytes):
//
//   client -> server:  magic(4) ver(1) ts(8) clientNonce(32)
//   server -> client:  serverNonce(32) serverTag(32)
//   client -> server:  clientTag(32)
//
// serverTag = HMAC-SHA256(psk, "ET-SERVER" | clientNonce | serverNonce)
// clientTag = HMAC-SHA256(psk, "ET-CLIENT" | clientNonce | serverNonce)
//
// Replay resistance: the server issues a fresh random serverNonce every
// connection, and clientTag is bound to it, so a recorded client transcript is
// useless against a new connection. The timestamp bounds accepted skew and lets
// the server cheaply drop stale probes before doing HMAC work.
const (
	magic       = 0x45540201 // "ET" + version 2.1
	protoVer    = 1
	nonceLen    = 32
	tagLen      = 32
	handshakeTO = 10 * time.Second
	maxSkew     = 5 * time.Minute
)

var (
	labelServer  = []byte("ET-SERVER")
	labelClient  = []byte("ET-CLIENT")
	labelC2SKey  = []byte("emergency-tunnel c2s key")
	labelS2CKey  = []byte("emergency-tunnel s2c key")
	errBadMagic  = fmt.Errorf("handshake: bad magic (not an emergency-tunnel peer)")
	errBadAuth   = fmt.Errorf("handshake: authentication failed (psk mismatch)")
	errStaleTime = fmt.Errorf("handshake: timestamp outside accepted window")
)

func tag(psk, label, cn, sn []byte) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write(label)
	m.Write(cn)
	m.Write(sn)
	return m.Sum(nil)
}

func deriveKey(psk, cn, sn, label []byte) []byte {
	salt := make([]byte, 0, len(cn)+len(sn))
	salt = append(salt, cn...)
	salt = append(salt, sn...)
	r := hkdf.New(sha256.New, psk, salt, label)
	key := make([]byte, 32)
	_, _ = io.ReadFull(r, key)
	return key
}

// ClientHandshake authenticates to the peer and returns an encrypted SecureConn.
// nowUnix is injected for testability; callers pass time.Now().Unix().
func ClientHandshake(conn net.Conn, cipherName string, psk []byte, nowUnix int64) (*SecureConn, error) {
	_ = conn.SetDeadline(time.Now().Add(handshakeTO))
	defer conn.SetDeadline(time.Time{})

	cn := make([]byte, nonceLen)
	if _, err := rand.Read(cn); err != nil {
		return nil, err
	}
	hdr := make([]byte, 4+1+8+nonceLen)
	binary.BigEndian.PutUint32(hdr[0:], magic)
	hdr[4] = protoVer
	binary.BigEndian.PutUint64(hdr[5:], uint64(nowUnix))
	copy(hdr[13:], cn)
	if _, err := conn.Write(hdr); err != nil {
		return nil, err
	}

	resp := make([]byte, nonceLen+tagLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("handshake: reading server response: %w", err)
	}
	sn := resp[:nonceLen]
	gotTag := resp[nonceLen:]
	if !hmac.Equal(gotTag, tag(psk, labelServer, cn, sn)) {
		return nil, errBadAuth
	}
	if _, err := conn.Write(tag(psk, labelClient, cn, sn)); err != nil {
		return nil, err
	}

	c2s := deriveKey(psk, cn, sn, labelC2SKey)
	s2c := deriveKey(psk, cn, sn, labelS2CKey)
	return wrap(conn, cipherName, c2s, s2c) // client sends c2s, receives s2c
}

// ServerHandshake validates an incoming peer and returns an encrypted SecureConn.
func ServerHandshake(conn net.Conn, cipherName string, psk []byte, nowUnix int64) (*SecureConn, error) {
	_ = conn.SetDeadline(time.Now().Add(handshakeTO))
	defer conn.SetDeadline(time.Time{})

	hdr := make([]byte, 4+1+8+nonceLen)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, fmt.Errorf("handshake: reading client hello: %w", err)
	}
	if binary.BigEndian.Uint32(hdr[0:]) != magic {
		return nil, errBadMagic
	}
	ts := int64(binary.BigEndian.Uint64(hdr[5:]))
	skew := nowUnix - ts
	if skew < 0 {
		skew = -skew
	}
	if skew > int64(maxSkew/time.Second) {
		return nil, errStaleTime
	}
	cn := hdr[13:]

	sn := make([]byte, nonceLen)
	if _, err := rand.Read(sn); err != nil {
		return nil, err
	}
	resp := make([]byte, nonceLen+tagLen)
	copy(resp[:nonceLen], sn)
	copy(resp[nonceLen:], tag(psk, labelServer, cn, sn))
	if _, err := conn.Write(resp); err != nil {
		return nil, err
	}

	gotTag := make([]byte, tagLen)
	if _, err := io.ReadFull(conn, gotTag); err != nil {
		return nil, fmt.Errorf("handshake: reading client tag: %w", err)
	}
	if !hmac.Equal(gotTag, tag(psk, labelClient, cn, sn)) {
		return nil, errBadAuth
	}

	c2s := deriveKey(psk, cn, sn, labelC2SKey)
	s2c := deriveKey(psk, cn, sn, labelS2CKey)
	return wrap(conn, cipherName, s2c, c2s) // server sends s2c, receives c2s
}
