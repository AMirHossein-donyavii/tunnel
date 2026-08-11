package l3

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emergency-tunnel/et/internal/crypto"
	"github.com/emergency-tunnel/et/internal/nettune"
	"github.com/emergency-tunnel/et/internal/transport"
)

// link carries encrypted "frames" between the two servers. A frame is a batch
// of length-prefixed packets (see datagram.go). The TUN engine treats every
// carrier uniformly through this interface; TCP uses a reliable stream, while
// UDP/ICMP use a datagram AEAD.
//
// One frame maps onto exactly one AEAD frame on a stream carrier and onto
// exactly one datagram on a packet carrier, so neither path pays for a second
// length header or an extra copy.
type link interface {
	// WriteFrame sends one encrypted frame (a [len][pkt]... payload) using a
	// single write syscall.
	WriteFrame(payload []byte) error
	// ReadFrame returns the next decrypted frame. The slice aliases an internal
	// buffer and is valid only until the next ReadFrame call.
	ReadFrame() ([]byte, error)
	// MaxFrame is the largest payload accepted by WriteFrame. It is a hard
	// carrier limit; how much the engine actually packs into a frame is governed
	// by frameBudget (see budget.go).
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
	// streamMaxFrame is the batch ceiling on a reliable carrier. It stays under
	// crypto.MaxPlaintext so a full batch is one AEAD frame and one write.
	streamMaxFrame = 60 * 1024
	// dgramMaxFrame keeps one full-size inner packet + framing inside one
	// carrier datagram, comfortably under a 1500-byte path MTU after AEAD and
	// UDP/ICMP/IP headers.
	dgramMaxFrame = 1400
)

// ---- TCP (reliable stream over crypto.SecureConn) --------------------------

type streamLink struct {
	sc *crypto.SecureConn
}

func (l *streamLink) WriteFrame(p []byte) error         { return l.sc.WriteFrame(p) }
func (l *streamLink) ReadFrame() ([]byte, error)        { return l.sc.NextFrame() }
func (l *streamLink) MaxFrame() int                     { return streamMaxFrame }
func (l *streamLink) SetReadDeadline(t time.Time) error { return l.sc.SetReadDeadline(t) }
func (l *streamLink) Close() error                      { return l.sc.Close() }

// ---- datagram (UDP / ICMP) over crypto.Datagram ---------------------------

// maxBadDatagrams bounds how many consecutive undecryptable datagrams are
// tolerated before the link is considered broken. A handful is normal on an
// open UDP port (scanners, stale packets from a previous session, replays); a
// continuous stream means the peer's keys no longer match ours.
const maxBadDatagrams = 64

// badDatagrams counts every datagram the AEAD refused (corrupt, forged or
// replayed) across all carriers. A process runs exactly one tunnel engine, so a
// package counter is the simplest way to surface this on /stats without
// threading engine state through every carrier constructor.
var badDatagrams atomic.Uint64

type datagramLink struct {
	conn net.Conn
	dg   *crypto.Datagram
	wbuf []byte
	rbuf []byte // raw ciphertext
	pbuf []byte // plaintext scratch
	bad  uint64 // consecutive undecryptable datagrams
}

func newDatagramLink(conn net.Conn, dg *crypto.Datagram) *datagramLink {
	return &datagramLink{
		conn: conn,
		dg:   dg,
		rbuf: make([]byte, dgramMaxFrame+crypto.DatagramOverhead+64),
		pbuf: make([]byte, 0, dgramMaxFrame+64),
	}
}

var errBadDatagramFlood = errors.New("l3: too many undecryptable datagrams — peer keys do not match")

func (l *datagramLink) WriteFrame(p []byte) error {
	l.wbuf = l.dg.Seal(l.wbuf[:0], p)
	_, err := l.conn.Write(l.wbuf)
	return err
}

// ReadFrame returns the next authenticated frame. A datagram that fails to
// decrypt is *skipped*, not fatal: on an unprotected UDP/ICMP carrier anyone can
// inject a packet, and tearing the tunnel down for each one would hand a remote
// attacker a trivial denial of service.
func (l *datagramLink) ReadFrame() ([]byte, error) {
	for {
		n, err := l.conn.Read(l.rbuf)
		if err != nil {
			return nil, err
		}
		pt, err := l.dg.Open(l.pbuf[:0], l.rbuf[:n])
		if err != nil {
			l.bad++
			badDatagrams.Add(1)
			if l.bad > maxBadDatagrams {
				return nil, errBadDatagramFlood
			}
			continue
		}
		l.bad = 0
		return pt, nil
	}
}

func (l *datagramLink) MaxFrame() int                     { return dgramMaxFrame }
func (l *datagramLink) SetReadDeadline(t time.Time) error { return l.conn.SetReadDeadline(t) }
func (l *datagramLink) Close() error                      { return l.conn.Close() }

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

// handshakeQueue runs peer handshakes off the accept path.
//
// Every carrier's listener has the same shape: something produces a candidate
// connection, and a handshake decides whether it is a peer. Running that
// handshake where the candidate is produced makes an unauthenticated stranger
// able to stall every real peer behind it, so each one runs in its own
// goroutine and only finished links come back through next().
type handshakeQueue struct {
	ready  chan link
	sem    chan struct{}
	closed chan struct{}
	once   sync.Once
}

// maxPendingHandshakes bounds the goroutines a flood of connections can create.
// It is far above any legitimate need — a tunnel opens one link per queue, a
// handful — so reaching it means something other than a peer is connecting, and
// shedding is the right answer.
const maxPendingHandshakes = 64

func newHandshakeQueue() *handshakeQueue {
	return &handshakeQueue{
		ready:  make(chan link, 8),
		sem:    make(chan struct{}, maxPendingHandshakes),
		closed: make(chan struct{}),
	}
}

// submit runs shake in its own goroutine and publishes the link it produces.
// When too many handshakes are already in flight the candidate is dropped
// rather than queued, so a flood costs a bounded amount and never delays a peer.
func (q *handshakeQueue) submit(shake func() (link, error), drop func()) {
	select {
	case q.sem <- struct{}{}:
	case <-q.closed:
		drop()
		return
	default:
		drop()
		return
	}
	go func() {
		defer func() { <-q.sem }()
		lk, err := shake()
		if err != nil {
			return // shake owns closing the candidate on failure
		}
		select {
		case q.ready <- lk:
		case <-q.closed:
			_ = lk.Close()
		}
	}()
}

func (q *handshakeQueue) next() (link, error) {
	select {
	case lk := <-q.ready:
		return lk, nil
	case <-q.closed:
		return nil, errListenerClosed
	}
}

func (q *handshakeQueue) close() { q.once.Do(func() { close(q.closed) }) }

var errListenerClosed = errors.New("link listener closed")

type tcpLinkListener struct {
	l      transport.Listener
	cipher string
	tune   nettune.Options

	once sync.Once
	q    *handshakeQueue
}

func (t *tcpLinkListener) AcceptLink() (link, error) {
	t.once.Do(t.start)
	return t.q.next()
}

// start runs the accept loop, handing each connection to the queue so its
// handshake happens in its own goroutine.
//
// Doing the handshake here instead would serialise it behind Accept: a peer
// that connects and then says nothing costs every connection queued behind it
// the full handshake timeout. On the listening side that address is public, so
// this is not a rare event — a port scan finds an open port within hours — and
// the effect is that the tunnel's own dialer cannot establish a link while a
// scanner is working through the port. Measured before this change: one silent
// connection delayed the first link by 9.6s, three by 29.7s, and enough of them
// held the tunnel down indefinitely.
func (t *tcpLinkListener) start() {
	go func() {
		for {
			raw, err := t.l.Accept()
			if err != nil {
				t.q.close()
				return
			}
			nettune.Apply(raw, t.tune)
			t.q.submit(func() (link, error) {
				sc, err := crypto.ServerHandshake(raw, t.cipher)
				if err != nil {
					_ = raw.Close()
					return nil, err
				}
				return &streamLink{sc: sc}, nil
			}, func() { _ = raw.Close() })
		}
	}()
}

func (t *tcpLinkListener) Close() error {
	t.q.close()
	return t.l.Close()
}
