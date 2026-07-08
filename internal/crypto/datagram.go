package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Datagram is a connectionless AEAD for the UDP/ICMP carriers. Unlike the
// stream SecureConn (sequential nonces), each packet carries an explicit 8-byte
// counter, so packet loss and reordering are tolerated — appropriate for a TUN
// tunnel, whose inner IP traffic is already loss-tolerant.
//
// Wire format per packet: [8-byte counter][ciphertext || tag].
type Datagram struct {
	send cipher.AEAD
	recv cipher.AEAD
	ctr  uint64
	sn   [12]byte // send nonce scratch (bytes 4..11 = counter)
	rn   [12]byte // recv nonce scratch
}

const dgNonceLen = 8

// DatagramOverhead is the per-packet expansion (counter + AEAD tag).
const DatagramOverhead = dgNonceLen + tagOverhead

func newDatagram(cipherName string, sendKey, recvKey []byte) (*Datagram, error) {
	s, err := newAEAD(cipherName, sendKey)
	if err != nil {
		return nil, err
	}
	r, err := newAEAD(cipherName, recvKey)
	if err != nil {
		return nil, err
	}
	return &Datagram{send: s, recv: r}, nil
}

// Seal encrypts plaintext, appending [counter][ciphertext||tag] to dst.
func (d *Datagram) Seal(dst, plaintext []byte) []byte {
	d.ctr++
	binary.BigEndian.PutUint64(d.sn[4:], d.ctr)
	var hdr [dgNonceLen]byte
	binary.BigEndian.PutUint64(hdr[:], d.ctr)
	dst = append(dst, hdr[:]...)
	return d.send.Seal(dst, d.sn[:], plaintext, nil)
}

// Open decrypts a packet produced by Seal into dst (which may be dst[:0]).
func (d *Datagram) Open(dst, packet []byte) ([]byte, error) {
	if len(packet) < DatagramOverhead {
		return nil, fmt.Errorf("crypto: short datagram (%d bytes)", len(packet))
	}
	ctr := binary.BigEndian.Uint64(packet[:dgNonceLen])
	binary.BigEndian.PutUint64(d.rn[4:], ctr)
	return d.recv.Open(dst, d.rn[:], packet[dgNonceLen:], nil)
}

// ClientHandshakePacket performs the X25519 exchange over a datagram conn
// (a connected UDP socket or an ICMP flow), retransmitting the hello until the
// server replies or the deadline passes.
func ClientHandshakePacket(conn net.Conn, cipherName string) (*Datagram, error) {
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

	buf := make([]byte, 128)
	deadline := time.Now().Add(handshakeTO)
	for attempt := 0; attempt < 8 && time.Now().Before(deadline); attempt++ {
		if _, err := conn.Write(hello); err != nil {
			return nil, err
		}
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n < pubLen {
			continue // timeout / short: retransmit
		}
		spub := buf[:pubLen]
		shared, err := curve25519.X25519(cpriv[:], spub)
		if err != nil {
			return nil, errECDH
		}
		_ = conn.SetReadDeadline(time.Time{})
		c2s := deriveKey(shared, cpub, spub, labelC2SKey)
		s2c := deriveKey(shared, cpub, spub, labelS2CKey)
		return newDatagram(cipherName, c2s, s2c) // client: send c2s, recv s2c
	}
	return nil, fmt.Errorf("packet handshake: no reply from server")
}

// ServerHandshakePacket completes the exchange for one inbound datagram flow.
// hello is the first datagram already read by the demultiplexer.
func ServerHandshakePacket(conn net.Conn, cipherName string, hello []byte) (*Datagram, error) {
	if len(hello) < 4+1+pubLen || binary.BigEndian.Uint32(hello) != magic || hello[4] != protoVer {
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
	return newDatagram(cipherName, s2c, c2s) // server: send s2c, recv c2s
}
