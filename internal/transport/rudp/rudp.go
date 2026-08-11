package rudp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/transport"
)

func init() { transport.Register(&rudpTransport{}) }

type rudpTransport struct{}

func (*rudpTransport) Name() string       { return "udp" }
func (*rudpTransport) Experimental() bool { return false }
func (*rudpTransport) Summary() string {
	return "Reliable UDP (ARQ + congestion control) — passes TCP-hostile paths"
}

func (*rudpTransport) NewDialer(cfg *config.Config, log *logx.Logger) (transport.Dialer, error) {
	if cfg.Peer == "" {
		return nil, fmt.Errorf("udp: peer is required on the dialing side")
	}
	return &dialer{
		addr: net.JoinHostPort(cfg.Peer, fmt.Sprintf("%d", cfg.TunnelPort)),
		opt:  optionsFor(cfg),
	}, nil
}

func (*rudpTransport) NewListener(cfg *config.Config, log *logx.Logger) (transport.Listener, error) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{Port: cfg.TunnelPort})
	if err != nil {
		return nil, fmt.Errorf("udp listen :%d: %w", cfg.TunnelPort, err)
	}
	if cfg.SoRcvbuf > 0 {
		_ = pc.SetReadBuffer(cfg.SoRcvbuf)
	}
	l := &listener{pc: pc, opt: optionsFor(cfg), conns: map[string]*Conn{}, accept: make(chan *Conn, 32), done: make(chan struct{})}
	go l.route()
	log.Info("reliable-UDP transport listening on :%d (mtu %d, %s)", cfg.TunnelPort, l.opt.mtu, l.opt.mode())
	return l, nil
}

// options carry the per-profile ARQ tuning.
type options struct {
	mtu      uint32
	sndWnd   uint32
	rcvWnd   uint32
	interval uint32
	nodelay  bool
	fec      FECParams
}

func (o options) mode() string {
	if o.nodelay {
		return "latency mode"
	}
	return "throughput mode"
}

// optionsFor derives ARQ tuning from the tunnel profile. The windows are in
// segments: at a 1376-byte MSS, 1024 segments is ~1.4 MB in flight, which
// covers a 100 ms path at ~110 Mbit.
func optionsFor(cfg *config.Config) options {
	o := options{mtu: defaultMTU, sndWnd: 1024, rcvWnd: 1024, interval: 10}
	if cfg.MTU > 0 && cfg.MTU < 1500 {
		o.mtu = uint32(cfg.MTU)
	}
	switch cfg.Profile {
	case config.ProfileFast:
		o.sndWnd, o.rcvWnd = 2048, 2048
	case config.ProfileResource:
		o.sndWnd, o.rcvWnd, o.interval = 256, 256, 20
	}
	// FEC trades a fixed share of the bandwidth for not spending a round trip on
	// each isolated loss. Both ends must configure the same split.
	o.fec = FECParams{Data: cfg.FECData, Parity: cfg.FECParity}

	// A gaming tunnel asks for latency: flush more often and back off gently.
	if cfg.LowLatency {
		o.nodelay = true
		o.interval = 5
		o.sndWnd, o.rcvWnd = 256, 256
	}
	return o
}

// ---- Conn -------------------------------------------------------------------

// Conn is a reliable stream over UDP presented as a net.Conn, so the crypto
// handshake, mux and forwarding layers above it need no changes at all.
type Conn struct {
	arq    *ARQ
	pc     *net.UDPConn
	remote *net.UDPAddr
	owned  bool // dialer side owns its socket; listener side shares one

	mu       sync.Mutex
	rbuf     []byte
	readable chan struct{}
	closed   chan struct{}
	closeOne sync.Once

	rdl, wdl time.Time
	start    time.Time

	fecEnc *fecEncoder
	fecDec *fecDecoder
	send   func([]byte)
}

func newConn(pc *net.UDPConn, remote *net.UDPAddr, conv uint32, owned bool, opt options) *Conn {
	c := &Conn{pc: pc, remote: remote, owned: owned,
		readable: make(chan struct{}, 1), closed: make(chan struct{}), start: time.Now()}

	// Bad parameters disable FEC rather than fail the tunnel: a link that runs
	// without error correction is worth far more than one that will not start.
	c.fecEnc, _ = newFECEncoder(opt.fec)
	c.fecDec, _ = newFECDecoder(opt.fec)

	raw := func(b []byte) {
		if owned {
			_, _ = pc.Write(b)
		} else {
			_, _ = pc.WriteToUDP(b, remote)
		}
	}
	// Every datagram leaves through here, the handshake included. Framing that
	// applies to some packets and not others cannot be undone by a receiver that
	// has no way to tell which it is holding.
	c.send = func(b []byte) {
		if len(b) == 0 {
			return
		}
		if c.fecEnc == nil {
			raw(b)
			return
		}
		for _, out := range c.fecEnc.encode(b) {
			raw(out)
		}
	}
	c.arq = newARQ(conv, func(b []byte) { c.send(b) })
	c.arq.SetMTU(opt.mtu)
	c.arq.SetWindow(opt.sndWnd, opt.rcvWnd)
	c.arq.SetNoDelay(opt.nodelay, opt.interval)
	c.arq.SetFECOverhead(opt.fec.Data, opt.fec.Parity)
	go c.updateLoop()
	return c
}

func (c *Conn) now() uint32 { return uint32(time.Since(c.start) / time.Millisecond) }

// updateLoop drives the ARQ timers: retransmission, ACK emission, probing.
func (c *Conn) updateLoop() {
	iv := time.Duration(c.arq.Interval()) * time.Millisecond
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-t.C:
			c.arq.Update(c.now())
			if c.arq.Dead() {
				c.Close()
				return
			}
			if c.arq.PendingRecv() {
				c.signal()
			}
		}
	}
}

func (c *Conn) signal() {
	select {
	case c.readable <- struct{}{}:
	default:
	}
}

// input feeds a datagram received for this connection. With FEC on, one
// datagram can yield several packets: the one that arrived, plus any the parity
// let us rebuild.
func (c *Conn) input(b []byte) {
	if c.fecDec == nil {
		if c.arq.Input(b) && c.arq.PendingRecv() {
			c.signal()
		}
		return
	}
	fed := false
	for _, pkt := range c.fecDec.decode(b) {
		if c.arq.Input(pkt) {
			fed = true
		}
	}
	if fed && c.arq.PendingRecv() {
		c.signal()
	}
}

func (c *Conn) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.rbuf) > 0 {
			n := copy(p, c.rbuf)
			c.rbuf = c.rbuf[n:]
			c.mu.Unlock()
			return n, nil
		}
		c.mu.Unlock()

		buf := make([]byte, 64*1024)
		if n := c.arq.Recv(buf); n > 0 {
			c.mu.Lock()
			c.rbuf = append(c.rbuf, buf[:n]...)
			c.mu.Unlock()
			continue
		}
		select {
		case <-c.closed:
			return 0, io.EOF
		case <-c.readable:
		case <-c.deadlineChan(c.rdl):
			return 0, timeoutError{}
		}
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	// Block until the ARQ has queue space. This is the backpressure the layers
	// above rely on: without it Write returns at memory speed while the wire
	// moves at cwnd per RTT, and the difference piles up in RAM.
	total := 0
	for len(p) > 0 {
		n := c.arq.Send(p)
		if n > 0 {
			total += n
			p = p[n:]
			c.arq.Update(c.now())
			continue
		}
		select {
		case <-c.closed:
			return total, net.ErrClosed
		case <-time.After(time.Duration(c.arq.Interval()) * time.Millisecond):
		case <-c.deadlineChan(c.wdl):
			return total, timeoutError{}
		}
	}
	return total, nil
}

func (c *Conn) deadlineChan(t time.Time) <-chan time.Time {
	if t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}
	return time.After(d)
}

func (c *Conn) Close() error {
	c.closeOne.Do(func() {
		c.arq.SendFIN()
		close(c.closed)
		if c.owned {
			_ = c.pc.Close()
		}
	})
	return nil
}

func (c *Conn) LocalAddr() net.Addr  { return c.pc.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.remote }
func (c *Conn) SetDeadline(t time.Time) error {
	c.rdl, c.wdl = t, t
	c.signal()
	return nil
}
func (c *Conn) SetReadDeadline(t time.Time) error  { c.rdl = t; c.signal(); return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { c.wdl = t; return nil }

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// ---- dialer -----------------------------------------------------------------

type dialer struct {
	addr string
	opt  options
}

func (d *dialer) Dial(ctx context.Context) (net.Conn, error) {
	raddr, err := net.ResolveUDPAddr("udp", d.addr)
	if err != nil {
		return nil, err
	}
	pc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	var cb [4]byte
	if _, err := rand.Read(cb[:]); err != nil {
		_ = pc.Close()
		return nil, err
	}
	conv := binary.BigEndian.Uint32(cb[:])
	if conv == 0 {
		conv = 1
	}
	c := newConn(pc, raddr, conv, true, d.opt)

	// Read loop for this connection's own socket.
	go func() {
		buf := make([]byte, 64*1024)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := pc.Read(buf)
			if err != nil {
				select {
				case <-c.closed:
					return
				default:
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				c.Close()
				return
			}
			c.input(buf[:n])
		}
	}()

	// Open the connection: a SYN that the listener turns into an accept. It is
	// retried because the first datagram of a UDP flow is the one most likely to
	// be dropped by a NAT that has not yet learned the mapping.
	if err := c.handshake(ctx); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (d *dialer) Close() error { return nil }

// handshake sends SYN until the peer acknowledges it.
func (c *Conn) handshake(ctx context.Context) error {
	deadline := time.Now().Add(10 * time.Second)
	s := &segment{conv: c.arq.conv, cmd: cmdSyn, wnd: uint16(defaultRcvWnd)}
	b := make([]byte, hdrLen)
	s.encode(b)
	for attempt := 0; attempt < 100 && time.Now().Before(deadline); attempt++ {
		c.send(b)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.closed:
			return net.ErrClosed
		case <-time.After(50 * time.Millisecond):
		}
		// The listener answers a SYN with an ACK, which advances the peer window
		// from its initial value — that is our signal the flow is established.
		if c.arq.established() {
			return nil
		}
	}
	return fmt.Errorf("udp: no response from %s", c.remote)
}

// established reports that at least one datagram has been received from the
// peer for this connection.
func (a *ARQ) established() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rcvNxt > 0 || len(a.ackList) > 0 || a.rxSrtt > 0 || a.sndUna > 0
}

// ---- listener ---------------------------------------------------------------

type listener struct {
	pc  *net.UDPConn
	opt options

	mu     sync.Mutex
	conns  map[string]*Conn
	accept chan *Conn

	closeOne sync.Once
	done     chan struct{}
}

// route demultiplexes the shared socket by peer address.
func (l *listener) route() {
	buf := make([]byte, 64*1024)
	for {
		n, src, err := l.pc.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-l.done:
				return
			default:
			}
			// A transient error must not strand every connection on this socket.
			continue
		}
		seg, ok := firstSegment(buf[:n], l.opt.fec.Enabled())
		if !ok {
			continue
		}
		key := src.String()
		l.mu.Lock()
		c := l.conns[key]
		l.mu.Unlock()

		if c == nil {
			// Only a SYN opens a connection; anything else from an unknown peer is
			// a stray or a scan and is ignored.
			if seg[4] != cmdSyn {
				continue
			}
			conv := binary.BigEndian.Uint32(seg[0:])
			c = newConn(l.pc, src, conv, false, l.opt)
			l.mu.Lock()
			l.conns[key] = c
			l.mu.Unlock()
			go l.reap(key, c)
			select {
			case l.accept <- c:
			default:
				c.Close()
				continue
			}
		}
		c.input(buf[:n])
	}
}

// reap forgets a connection once it closes, so the map cannot grow without
// bound on a public port.
func (l *listener) reap(key string, c *Conn) {
	<-c.closed
	l.mu.Lock()
	if l.conns[key] == c {
		delete(l.conns, key)
	}
	l.mu.Unlock()
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *listener) Addr() net.Addr { return l.pc.LocalAddr() }

func (l *listener) Close() error {
	l.closeOne.Do(func() { close(l.done); _ = l.pc.Close() })
	return nil
}
