package l3

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/emergency-tunnel/et/internal/crypto"
	"github.com/emergency-tunnel/et/internal/nettune"
	"github.com/emergency-tunnel/et/internal/transport"
)

// link carries encrypted "frames" between the two servers. A frame is a batch
// of length-prefixed packets (see datagram.go). The TUN engine treats every
// carrier uniformly through this interface; TCP uses a reliable stream, while
// UDP/ICMP use a datagram AEAD.
type link interface {
	// WriteFrame sends one encrypted frame (a [len][pkt]... payload).
	WriteFrame(payload []byte) error
	// ReadFrame reads one decrypted frame into buf, returning its length.
	ReadFrame(buf []byte) (int, error)
	// MaxFrame is the largest payload accepted by WriteFrame.
	MaxFrame() int
	SetReadDeadline(t time.Time) error
	Close() error
}

// linkDialer establishes outbound links (Kharej / dialing side).
type linkDialer interface {
	DialLink(ctx context.Context) (link, error)
	Close() error
}

// linkListener accepts inbound links (Iran / listening side).
type linkListener interface {
	AcceptLink() (link, error)
	Close() error
}

const (
	streamMaxFrame = 60 * 1024 // TCP: large batches
	// dgramMaxFrame keeps one full-size inner packet + framing inside one
	// carrier datagram, comfortably under a 1500-byte path MTU after AEAD and
	// UDP/ICMP/IP headers.
	dgramMaxFrame = 1400
)

// ---- TCP (reliable stream over crypto.SecureConn) --------------------------

type streamLink struct {
	sc   *crypto.SecureConn
	wbuf []byte
}

func (l *streamLink) WriteFrame(p []byte) error {
	l.wbuf = l.wbuf[:0]
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(p)))
	l.wbuf = append(l.wbuf, h[:]...)
	l.wbuf = append(l.wbuf, p...)
	_, err := l.sc.Write(l.wbuf)
	return err
}

func (l *streamLink) ReadFrame(buf []byte) (int, error) {
	var h [4]byte
	if _, err := io.ReadFull(l.sc, h[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint32(h[:]))
	if n > len(buf) {
		return 0, fmt.Errorf("l3: frame too large (%d)", n)
	}
	if _, err := io.ReadFull(l.sc, buf[:n]); err != nil {
		return 0, err
	}
	return n, nil
}

func (l *streamLink) MaxFrame() int                   { return streamMaxFrame }
func (l *streamLink) SetReadDeadline(t time.Time) error { return l.sc.SetReadDeadline(t) }
func (l *streamLink) Close() error                    { return l.sc.Close() }

// ---- datagram (UDP / ICMP) over crypto.Datagram ---------------------------

type datagramLink struct {
	conn net.Conn
	dg   *crypto.Datagram
	wbuf []byte
	rbuf []byte
}

func newDatagramLink(conn net.Conn, dg *crypto.Datagram) *datagramLink {
	return &datagramLink{conn: conn, dg: dg, rbuf: make([]byte, dgramMaxFrame+crypto.DatagramOverhead+64)}
}

func (l *datagramLink) WriteFrame(p []byte) error {
	l.wbuf = l.dg.Seal(l.wbuf[:0], p)
	_, err := l.conn.Write(l.wbuf)
	return err
}

func (l *datagramLink) ReadFrame(buf []byte) (int, error) {
	n, err := l.conn.Read(l.rbuf)
	if err != nil {
		return 0, err
	}
	pt, err := l.dg.Open(buf[:0], l.rbuf[:n])
	if err != nil {
		return 0, err
	}
	return len(pt), nil
}

func (l *datagramLink) MaxFrame() int                   { return dgramMaxFrame }
func (l *datagramLink) SetReadDeadline(t time.Time) error { return l.conn.SetReadDeadline(t) }
func (l *datagramLink) Close() error                    { return l.conn.Close() }

// ---- TCP factory (reuses the tcp transport + stream handshake) -------------

type tcpLinkDialer struct {
	d      transport.Dialer
	cipher string
	tune   nettune.Options
}

func (t *tcpLinkDialer) DialLink(ctx context.Context) (link, error) {
	raw, err := t.d.Dial(ctx)
	if err != nil {
		return nil, err
	}
	nettune.Apply(raw, t.tune)
	sc, err := crypto.ClientHandshake(raw, t.cipher)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return &streamLink{sc: sc}, nil
}
func (t *tcpLinkDialer) Close() error { return t.d.Close() }

type tcpLinkListener struct {
	l      transport.Listener
	cipher string
	tune   nettune.Options
}

func (t *tcpLinkListener) AcceptLink() (link, error) {
	raw, err := t.l.Accept()
	if err != nil {
		return nil, err
	}
	nettune.Apply(raw, t.tune)
	sc, err := crypto.ServerHandshake(raw, t.cipher)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return &streamLink{sc: sc}, nil
}
func (t *tcpLinkListener) Close() error { return t.l.Close() }
