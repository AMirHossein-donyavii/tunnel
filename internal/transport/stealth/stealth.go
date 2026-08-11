// Package stealth carries the tunnel inside a stream that has no fingerprint.
//
// Every other transport announces itself. Ours announces itself twice over: the
// core handshake opens with the constant bytes 45 54 02 03 03, at offset zero of
// the first packet of every connection, and any peer that reaches the port
// completes the exchange — so a scanner not only recognises the tunnel, it can
// confirm it.
//
// This transport removes both. The handshake is an ephemeral X25519 exchange
// where each message is a 32-byte public key followed by a MAC keyed on a
// pre-shared token: uniform bytes with no header, no version, no constant. The
// MAC is checked before anything is sent back, so a peer without the token gets
// silence rather than a reply — a port scan finds a dead port instead of a
// service to fingerprint.
//
// What rides inside is the ordinary tunnel. The core handshake, its magic, the
// mux and everything above run unchanged on top of this, which means the
// fingerprint that used to be on the wire is now inside an encrypted stream
// where nothing can match it. The cost is a second layer of encryption; on a
// path where the connection itself is being filtered, that is a good trade.
//
// Record sizes leak too. Encryption settles what is in a record and says nothing
// about how long it is, and lengths alone carry a shape: a heartbeat, a
// handshake of known size, full-sized records for a download and small ones for
// an interactive session. So each record carries a random amount of filler, and
// the filler length lives under the AEAD rather than beside it — padding an
// observer can read and subtract is not padding.
package stealth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	keyLen  = 32
	macLen  = 16
	nonceSz = chacha20poly1305.NonceSize

	// handshakeMsg is one side's message: an ephemeral public key and a MAC over
	// it. Both are indistinguishable from random to anyone without the token.
	handshakeMsg = keyLen + macLen

	// maxRecord bounds a single encrypted record's plaintext.
	maxRecord = 16 * 1024

	// maxPad is the most filler a record can carry. A byte's worth: enough that
	// a record's length says little about its payload, cheap enough that the
	// average cost is noise against a full-sized record.
	maxPad = 255

	handshakeTimeout = 15 * time.Second
)

var (
	// ErrAuth is returned when a peer cannot prove it holds the token. The
	// listener never writes anything in this case.
	ErrAuth = errors.New("stealth: peer did not authenticate")

	errBadRecord = errors.New("stealth: record failed authentication")
	errTooLarge  = errors.New("stealth: record too large")
)

// Handshake context strings. They are mixed into the key schedule and the MACs
// but never sent, so they bind this exchange to this protocol without putting
// anything on the wire that identifies it.
var (
	ctxClientMAC = []byte("emergency-tunnel stealth client v1")
	ctxServerMAC = []byte("emergency-tunnel stealth server v1")
	ctxKeys      = []byte("emergency-tunnel stealth keys v1")
)

// psk derives the 32-byte pre-shared key from the tunnel token.
func psk(token string) []byte {
	k := make([]byte, keyLen)
	r := hkdf.New(sha256.New, []byte(token), []byte("emergency-tunnel stealth psk v1"), nil)
	_, _ = io.ReadFull(r, k)
	return k
}

// tag authenticates a public key under the pre-shared key.
func tag(k, pub, context []byte) []byte {
	m := hmac.New(sha256.New, k)
	m.Write(context)
	m.Write(pub)
	return m.Sum(nil)[:macLen]
}

// ClientHandshake performs the initiator side over raw and returns an encrypted
// connection.
func ClientHandshake(raw net.Conn, token string, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = handshakeTimeout
	}
	_ = raw.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = raw.SetDeadline(time.Time{}) }()

	k := psk(token)
	cpriv, cpub, err := keypair()
	if err != nil {
		return nil, err
	}

	msg := make([]byte, 0, handshakeMsg)
	msg = append(msg, cpub...)
	msg = append(msg, tag(k, cpub, ctxClientMAC)...)
	if _, err := raw.Write(msg); err != nil {
		return nil, err
	}

	in := make([]byte, handshakeMsg)
	if _, err := io.ReadFull(raw, in); err != nil {
		return nil, err
	}
	spub := in[:keyLen]
	if !hmac.Equal(in[keyLen:], tag(k, spub, ctxServerMAC)) {
		return nil, ErrAuth
	}
	shared, err := curve25519.X25519(cpriv, spub)
	if err != nil {
		return nil, err
	}
	c2s, s2c := deriveKeys(shared, k, cpub, spub)
	return newConn(raw, c2s, s2c)
}

// ServerHandshake is the responder side. A peer that cannot prove it holds the
// token gets no reply at all — the connection is simply closed, so a probe
// cannot tell this port from a closed one by what comes back.
func ServerHandshake(raw net.Conn, token string, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = handshakeTimeout
	}
	_ = raw.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = raw.SetDeadline(time.Time{}) }()

	k := psk(token)
	in := make([]byte, handshakeMsg)
	if _, err := io.ReadFull(raw, in); err != nil {
		return nil, err
	}
	cpub := in[:keyLen]
	if !hmac.Equal(in[keyLen:], tag(k, cpub, ctxClientMAC)) {
		return nil, ErrAuth
	}

	spriv, spub, err := keypair()
	if err != nil {
		return nil, err
	}
	shared, err := curve25519.X25519(spriv, cpub)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, 0, handshakeMsg)
	msg = append(msg, spub...)
	msg = append(msg, tag(k, spub, ctxServerMAC)...)
	if _, err := raw.Write(msg); err != nil {
		return nil, err
	}
	c2s, s2c := deriveKeys(shared, k, cpub, spub)
	return newConn(raw, s2c, c2s)
}

func keypair() (priv, pub []byte, err error) {
	priv = make([]byte, keyLen)
	if _, err = rand.Read(priv); err != nil {
		return nil, nil, err
	}
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	return priv, pub, err
}

// deriveKeys mixes the token into the key schedule alongside the shared secret,
// so knowing one without the other is not enough to read the stream.
func deriveKeys(shared, k, cpub, spub []byte) (c2s, s2c []byte) {
	salt := make([]byte, 0, len(k)+2*keyLen)
	salt = append(salt, k...)
	salt = append(salt, cpub...)
	salt = append(salt, spub...)
	r := hkdf.New(sha256.New, shared, salt, ctxKeys)
	c2s, s2c = make([]byte, keyLen), make([]byte, keyLen)
	_, _ = io.ReadFull(r, c2s)
	_, _ = io.ReadFull(r, s2c)
	return c2s, s2c
}

// conn is the encrypted record layer.
type conn struct {
	net.Conn
	wmu  sync.Mutex
	rmu  sync.Mutex
	send *cipherState
	recv *cipherState

	hdr   [2]byte
	rbuf  []byte
	plain []byte
	left  []byte // decrypted bytes not yet handed to Read
}

func newConn(raw net.Conn, sendKey, recvKey []byte) (net.Conn, error) {
	s, err := newCipherState(sendKey)
	if err != nil {
		return nil, err
	}
	r, err := newCipherState(recvKey)
	if err != nil {
		return nil, err
	}
	return &conn{Conn: raw, send: s, recv: r,
		rbuf:  make([]byte, maxRecord+maxPad+1+chacha20poly1305.Overhead),
		plain: make([]byte, 0, maxRecord+maxPad+1)}, nil
}

// NetConn returns the connection underneath the stealth record layer, so
// nettune.Apply can reach the TCP socket to tune it (see nettune.baseTCPConn).
func (c *conn) NetConn() net.Conn { return c.Conn }

func (c *conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxRecord {
			n = maxRecord
		}
		if err := c.writeRecord(p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// writeRecord seals one record: a length byte, the payload, and filler. All
// three are inside the AEAD, so the only thing on the wire is a record whose
// length moved.
func (c *conn) writeRecord(p []byte) error {
	var padByte [1]byte
	if _, err := rand.Read(padByte[:]); err != nil {
		return err
	}
	pad := int(padByte[0])

	buf := make([]byte, 1+len(p)+pad)
	buf[0] = byte(pad)
	copy(buf[1:], p)
	// The filler is left as zeroes: it is encrypted before it is sent, so its
	// content is already indistinguishable from anything else. Only its length
	// has to be unpredictable, and that is what was drawn.

	out := c.send.seal(nil, buf)
	if len(out) > 0xFFFF {
		return errTooLarge
	}
	frame := make([]byte, 2+len(out))
	binary.BigEndian.PutUint16(frame, uint16(len(out)))
	copy(frame[2:], out)
	_, err := c.Conn.Write(frame)
	return err
}

func (c *conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.left) == 0 {
		if err := c.readRecord(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.left)
	c.left = c.left[n:]
	return n, nil
}

func (c *conn) readRecord() error {
	if _, err := io.ReadFull(c.Conn, c.hdr[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(c.hdr[:]))
	if n == 0 || n > len(c.rbuf) {
		return errTooLarge
	}
	if _, err := io.ReadFull(c.Conn, c.rbuf[:n]); err != nil {
		return err
	}
	pt, err := c.recv.open(c.plain[:0], c.rbuf[:n])
	if err != nil {
		return errBadRecord
	}
	if len(pt) < 1 {
		return errBadRecord
	}
	pad := int(pt[0])
	if 1+pad > len(pt) {
		return errBadRecord
	}
	c.left = pt[1 : len(pt)-pad]
	return nil
}

// cipherState is a ChaCha20-Poly1305 key with a counter nonce. Records are
// numbered, so a reordered, replayed or dropped record fails to open.
type cipherState struct {
	aead interface {
		Seal(dst, nonce, plaintext, ad []byte) []byte
		Open(dst, nonce, ciphertext, ad []byte) ([]byte, error)
	}
	n     uint64
	nonce [nonceSz]byte
}

func newCipherState(key []byte) (*cipherState, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("stealth: cipher: %w", err)
	}
	return &cipherState{aead: a}, nil
}

func (s *cipherState) next() []byte {
	binary.LittleEndian.PutUint64(s.nonce[4:], s.n)
	s.n++
	return s.nonce[:]
}

func (s *cipherState) seal(dst, pt []byte) []byte { return s.aead.Seal(dst, s.next(), pt, nil) }

func (s *cipherState) open(dst, ct []byte) ([]byte, error) {
	return s.aead.Open(dst, s.next(), ct, nil)
}
