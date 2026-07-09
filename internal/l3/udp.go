package l3

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/emergency-tunnel/et/internal/crypto"
)

// UDP carrier: each encrypted frame is one UDP datagram. Point-to-point between
// the two servers. The dialer opens `pool` connected sockets; the listener binds
// one socket and demultiplexes inbound datagrams by source address into flows.

type udpLinkDialer struct {
	addr           string
	cipher         string
	sndbuf, rcvbuf int
}

func (u *udpLinkDialer) DialLink(ctx context.Context) (link, error) {
	raddr, err := net.ResolveUDPAddr("udp", u.addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	setUDPBuffers(conn, u.sndbuf, u.rcvbuf)
	dg, err := crypto.ClientHandshakePacket(conn, u.cipher)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return newDatagramLink(conn, dg), nil
}

func (u *udpLinkDialer) Close() error { return nil }

type udpLinkListener struct {
	pc     *net.UDPConn
	cipher string

	mu     sync.Mutex
	flows  map[string]*udpFlow
	accept chan *udpFlow

	closeOnce sync.Once
	closed    chan struct{}
}

// setUDPBuffers applies best-effort socket buffer sizes; failures are ignored so
// a restrictive kernel never breaks the carrier.
func setUDPBuffers(c *net.UDPConn, snd, rcv int) {
	if rcv > 0 {
		_ = c.SetReadBuffer(rcv)
	}
	if snd > 0 {
		_ = c.SetWriteBuffer(snd)
	}
}

func newUDPListener(port, sndbuf, rcvbuf int, cipher string) (*udpLinkListener, error) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, fmt.Errorf("udp listen :%d: %w", port, err)
	}
	setUDPBuffers(pc, sndbuf, rcvbuf)
	l := &udpLinkListener{
		pc:     pc,
		cipher: cipher,
		flows:  make(map[string]*udpFlow),
		accept: make(chan *udpFlow, 64),
		closed: make(chan struct{}),
	}
	go l.route()
	return l, nil
}

// route reads every inbound datagram and dispatches it to its flow.
func (l *udpLinkListener) route() {
	buf := make([]byte, 64*1024)
	for {
		n, src, err := l.pc.ReadFromUDP(buf)
		if err != nil {
			l.Close()
			return
		}
		key := src.String()
		l.mu.Lock()
		f := l.flows[key]
		l.mu.Unlock()

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		if f == nil {
			f = &udpFlow{pc: l.pc, src: src, key: key, l: l, in: make(chan []byte, 256), firstMsg: pkt, closed: make(chan struct{})}
			l.mu.Lock()
			l.flows[key] = f
			l.mu.Unlock()
			select {
			case l.accept <- f:
			default: // accept backlog full: drop the new flow
				l.remove(key)
			}
		} else {
			select {
			case f.in <- pkt:
			case <-f.closed:
			default: // flow buffer full: drop (inner IP retransmits)
			}
		}
	}
}

func (l *udpLinkListener) remove(key string) {
	l.mu.Lock()
	delete(l.flows, key)
	l.mu.Unlock()
}

func (l *udpLinkListener) AcceptLink() (link, error) {
	for {
		select {
		case f := <-l.accept:
			dg, err := crypto.ServerHandshakePacket(f, l.cipher, f.firstMsg)
			if err != nil {
				f.Close()
				continue
			}
			return newDatagramLink(f, dg), nil
		case <-l.closed:
			return nil, errors.New("udp listener closed")
		}
	}
}

func (l *udpLinkListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
		_ = l.pc.Close()
	})
	return nil
}

// udpFlow presents one demultiplexed peer as a net.Conn for the handshake and
// datagram link.
type udpFlow struct {
	pc       *net.UDPConn
	src      *net.UDPAddr
	key      string
	l        *udpLinkListener
	in       chan []byte
	firstMsg []byte

	dmu      sync.Mutex
	deadline time.Time

	closeOnce sync.Once
	closed    chan struct{}
}

func (f *udpFlow) Read(b []byte) (int, error) {
	f.dmu.Lock()
	dl := f.deadline
	f.dmu.Unlock()
	var timer *time.Timer
	var timeout <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, timeoutErr{}
		}
		timer = time.NewTimer(d)
		timeout = timer.C
		defer timer.Stop()
	}
	select {
	case pkt := <-f.in:
		return copy(b, pkt), nil
	case <-timeout:
		return 0, timeoutErr{}
	case <-f.closed:
		return 0, net.ErrClosed
	}
}

func (f *udpFlow) Write(b []byte) (int, error) { return f.pc.WriteToUDP(b, f.src) }

func (f *udpFlow) SetReadDeadline(t time.Time) error {
	f.dmu.Lock()
	f.deadline = t
	f.dmu.Unlock()
	return nil
}

func (f *udpFlow) Close() error {
	f.closeOnce.Do(func() { close(f.closed); f.l.remove(f.key) })
	return nil
}

// The remaining net.Conn methods are unused by the link/handshake layer.
func (f *udpFlow) LocalAddr() net.Addr                { return f.pc.LocalAddr() }
func (f *udpFlow) RemoteAddr() net.Addr               { return f.src }
func (f *udpFlow) SetDeadline(t time.Time) error      { return f.SetReadDeadline(t) }
func (f *udpFlow) SetWriteDeadline(t time.Time) error { return nil }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
