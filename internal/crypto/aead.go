// Package crypto provides the encrypted AEAD framing used on every Emergency
// Tunnel link, plus an ephemeral X25519 key-exchange handshake (no pre-shared
// key) that derives the per-direction session keys.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// MaxPlaintext bounds a single frame's payload. 16 KiB keeps per-connection
	// buffers small (important on 2-core / 2-4 GB VPS targets) while amortising
	// the AEAD tag and length prefix over a useful chunk.
	MaxPlaintext = 16 * 1024
	tagOverhead  = 16 // Poly1305 / GCM tag
	lenPrefix    = 2
)

// newAEAD builds an AEAD for the named cipher and 32-byte key.
func newAEAD(name string, key []byte) (cipher.AEAD, error) {
	switch name {
	case "chacha20-poly1305":
		return chacha20poly1305.New(key)
	case "aes-256-gcm":
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return nil, fmt.Errorf("unsupported cipher %q", name)
	}
}

// SecureConn wraps a net.Conn with per-direction AEAD framing. One goroutine
// may call Read while another calls Write concurrently (the standard splice
// pattern); each direction keeps independent key material and a monotonic
// nonce counter, so no locking is required for that pattern.
type SecureConn struct {
	net.Conn
	send    cipher.AEAD
	recv    cipher.AEAD
	sendCtr uint64
	recvCtr uint64

	sendBuf   []byte // reusable ciphertext scratch (writer goroutine only)
	sendNonce [12]byte
	recvNonce [12]byte

	leftover []byte // decrypted bytes not yet consumed by Read
	frameBuf []byte // reusable ciphertext read buffer
}

// wrap constructs a SecureConn from an established handshake.
func wrap(conn net.Conn, cipherName string, sendKey, recvKey []byte) (*SecureConn, error) {
	s, err := newAEAD(cipherName, sendKey)
	if err != nil {
		return nil, err
	}
	r, err := newAEAD(cipherName, recvKey)
	if err != nil {
		return nil, err
	}
	return &SecureConn{
		Conn:     conn,
		send:     s,
		recv:     r,
		sendBuf:  make([]byte, 0, MaxPlaintext+tagOverhead),
		frameBuf: make([]byte, MaxPlaintext+tagOverhead),
	}, nil
}

// Write encrypts p as one or more frames.
func (s *SecureConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > MaxPlaintext {
			chunk = chunk[:MaxPlaintext]
		}
		binary.BigEndian.PutUint64(s.sendNonce[4:], s.sendCtr)
		ct := s.send.Seal(s.sendBuf[:0], s.sendNonce[:], chunk, nil)
		s.sendCtr++
		var lb [lenPrefix]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(ct)))
		if _, err := s.Conn.Write(lb[:]); err != nil {
			return total, err
		}
		if _, err := s.Conn.Write(ct); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Read returns decrypted plaintext, reassembling frames as needed.
func (s *SecureConn) Read(p []byte) (int, error) {
	if len(s.leftover) > 0 {
		n := copy(p, s.leftover)
		s.leftover = s.leftover[n:]
		return n, nil
	}
	var lb [lenPrefix]byte
	if _, err := io.ReadFull(s.Conn, lb[:]); err != nil {
		return 0, err
	}
	clen := int(binary.BigEndian.Uint16(lb[:]))
	if clen < tagOverhead || clen > MaxPlaintext+tagOverhead {
		return 0, fmt.Errorf("invalid frame length %d", clen)
	}
	ct := s.frameBuf[:clen]
	if _, err := io.ReadFull(s.Conn, ct); err != nil {
		return 0, err
	}
	binary.BigEndian.PutUint64(s.recvNonce[4:], s.recvCtr)
	pt, err := s.recv.Open(ct[:0], s.recvNonce[:], ct, nil)
	if err != nil {
		return 0, fmt.Errorf("frame authentication failed: %w", err)
	}
	s.recvCtr++
	n := copy(p, pt)
	if n < len(pt) {
		// Stash the remainder for the next Read.
		s.leftover = append(s.leftover[:0], pt[n:]...)
	}
	return n, nil
}
