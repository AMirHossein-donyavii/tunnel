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
	// MaxPlaintext bounds a single frame's payload. 63 KiB is the largest value
	// whose sealed form (payload + tag) still fits the 16-bit length prefix, so a
	// full L3 packet batch or a coalesced mux write becomes ONE frame and ONE
	// write syscall instead of four.
	MaxPlaintext = 63 * 1024
	tagOverhead  = 16 // Poly1305 / GCM tag
	lenPrefix    = 2
	// maxCipherFrame is the largest on-wire frame body (must fit uint16).
	maxCipherFrame = MaxPlaintext + tagOverhead

	// DefaultFrameSize is the plaintext chunk a stream-mode Write seals into one
	// frame. It matches the read buffer sized at construction, so a connection
	// that never sends larger frames never grows past ~32 KiB of scratch.
	DefaultFrameSize = 32 * 1024

	// maxWriteBurst caps how many sealed frames are coalesced into a single
	// Conn.Write. Bounded so a huge Write cannot balloon the scratch buffer.
	maxWriteBurst = 128 * 1024
)

// ErrFrameTooLarge is returned by WriteFrame for payloads above MaxPlaintext.
var ErrFrameTooLarge = fmt.Errorf("crypto: frame exceeds %d bytes", MaxPlaintext)

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
// may call Read/ReadFrame/NextFrame while another calls Write/WriteFrame (the
// standard splice pattern); each direction keeps independent key material,
// scratch buffers and a monotonic nonce counter, so no locking is required for
// that pattern. Two concurrent writers (or two readers) are NOT supported.
//
// The wire format is a sequence of [uint16 len][ciphertext||tag] frames. Frames
// are written with a single Conn.Write — never a separate write for the length
// prefix, which with TCP_NODELAY would put a 2-byte segment on the wire ahead of
// every frame.
type SecureConn struct {
	net.Conn
	send    cipher.AEAD
	recv    cipher.AEAD
	sendCtr uint64
	recvCtr uint64

	frameSize int    // max plaintext per frame for stream-mode Write
	sendBuf   []byte // reusable sealed-frame scratch (writer goroutine only)
	sendNonce [12]byte
	recvNonce [12]byte

	leftover []byte // undelivered plaintext; aliases recvBuf, never copied
	recvBuf  []byte // reusable ciphertext read buffer (decrypted in place)
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
		Conn:      conn,
		send:      s,
		recv:      r,
		frameSize: DefaultFrameSize,
		sendBuf:   make([]byte, 0, DefaultFrameSize+tagOverhead+lenPrefix),
		recvBuf:   make([]byte, DefaultFrameSize+tagOverhead),
	}, nil
}

// SetFrameSize sets the maximum plaintext sealed into one frame by stream-mode
// Write. Larger frames amortise the tag and the syscall over more bytes;
// smaller frames bound how much must arrive before the peer can decrypt. Values
// are clamped to [1 KiB, MaxPlaintext]. WriteFrame is not affected — it always
// sends exactly one frame of the payload it is given.
func (s *SecureConn) SetFrameSize(n int) {
	switch {
	case n < 1024:
		n = 1024
	case n > MaxPlaintext:
		n = MaxPlaintext
	}
	s.frameSize = n
}

// seal appends one [len][ciphertext||tag] frame for chunk to dst.
func (s *SecureConn) seal(dst, chunk []byte) []byte {
	off := len(dst)
	dst = append(dst, 0, 0) // length placeholder
	binary.BigEndian.PutUint64(s.sendNonce[4:], s.sendCtr)
	s.sendCtr++
	dst = s.send.Seal(dst, s.sendNonce[:], chunk, nil)
	binary.BigEndian.PutUint16(dst[off:off+lenPrefix], uint16(len(dst)-off-lenPrefix))
	return dst
}

// WriteFrame seals p as exactly one frame and emits it with one write syscall.
// It is the message-oriented counterpart to Write, used by the L3 engine so a
// packet batch needs no second length header of its own.
func (s *SecureConn) WriteFrame(p []byte) error {
	if len(p) > MaxPlaintext {
		return ErrFrameTooLarge
	}
	s.sendBuf = s.seal(s.sendBuf[:0], p)
	_, err := s.Conn.Write(s.sendBuf)
	return err
}

// Write encrypts p as one or more frames, coalescing them into as few write
// syscalls as possible.
func (s *SecureConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		s.sendBuf = s.sendBuf[:0]
		staged := 0
		for staged < len(p) && len(s.sendBuf) < maxWriteBurst {
			chunk := p[staged:]
			if len(chunk) > s.frameSize {
				chunk = chunk[:s.frameSize]
			}
			s.sendBuf = s.seal(s.sendBuf, chunk)
			staged += len(chunk)
		}
		if _, err := s.Conn.Write(s.sendBuf); err != nil {
			return written, err
		}
		written += staged
		p = p[staged:]
	}
	return written, nil
}

// readSealed reads one frame body into the reusable receive buffer.
func (s *SecureConn) readSealed() ([]byte, error) {
	var lb [lenPrefix]byte
	if _, err := io.ReadFull(s.Conn, lb[:]); err != nil {
		return nil, err
	}
	clen := int(binary.BigEndian.Uint16(lb[:]))
	if clen < tagOverhead || clen > maxCipherFrame {
		return nil, fmt.Errorf("crypto: invalid frame length %d", clen)
	}
	if cap(s.recvBuf) < clen {
		s.recvBuf = make([]byte, clen)
	}
	ct := s.recvBuf[:clen]
	if _, err := io.ReadFull(s.Conn, ct); err != nil {
		return nil, err
	}
	return ct, nil
}

// open decrypts a frame body in place and returns the plaintext, which aliases
// the receive buffer and stays valid until the next read.
func (s *SecureConn) open(ct []byte) ([]byte, error) {
	binary.BigEndian.PutUint64(s.recvNonce[4:], s.recvCtr)
	pt, err := s.recv.Open(ct[:0], s.recvNonce[:], ct, nil)
	if err != nil {
		return nil, fmt.Errorf("frame authentication failed: %w", err)
	}
	s.recvCtr++
	return pt, nil
}

// NextFrame returns the next decrypted frame. The slice aliases an internal
// buffer and is only valid until the following NextFrame/Read call — callers
// that need to retain the bytes must copy them. This is the zero-copy read path
// used by the L3 engine.
func (s *SecureConn) NextFrame() ([]byte, error) {
	ct, err := s.readSealed()
	if err != nil {
		return nil, err
	}
	return s.open(ct)
}

// Read returns decrypted plaintext, reassembling frames as needed. Undelivered
// bytes are kept as a slice of the receive buffer rather than copied out, so a
// caller that reads a small header followed by a payload costs no extra memcpy.
func (s *SecureConn) Read(p []byte) (int, error) {
	for len(s.leftover) == 0 {
		pt, err := s.NextFrame()
		if err != nil {
			return 0, err
		}
		s.leftover = pt
	}
	n := copy(p, s.leftover)
	s.leftover = s.leftover[n:]
	return n, nil
}
