//go:build linux

// Raw-IP carriers for the TUN engine: IP-in-IP (protocol 4) and GRE (protocol
// 47). See ipx.go for the wire format and why these protocols are worth having.
//
// The shape mirrors the ICMP carrier exactly, and for the same reasons: one raw
// socket per side rather than one per link, because a raw socket has no port and
// the kernel copies every packet of that protocol into every socket that is
// open for it; a single read loop that demultiplexes by link id; and a bounded
// per-link queue that drops rather than stalling the loop, since one slow link
// must never stop the others being read.
//
// Requires CAP_NET_RAW.
package l3

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/crypto"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/nettune"
)

func newIPXCarrier(mode string, cfg *config.Config, isDialer bool, cipher string, log *logx.Logger) (linkDialer, linkListener, error) {
	p, ok := ipxProfileFor(mode)
	if !ok {
		return nil, nil, fmt.Errorf("unknown IPX profile %q", mode)
	}
	if isDialer {
		return &ipxLinkDialer{p: p, peer: cfg.Peer, cipher: cipher, cfg: cfg,
			tunnel: cfg.TunnelPort, log: log}, nil, nil
	}
	pc, err := net.ListenPacket(p.network, listenAddrFor(cfg))
	if err != nil {
		return nil, nil, fmt.Errorf("%s listen (%s): %w (needs CAP_NET_RAW)", p.label, p.network, err)
	}
	tuneRawSocket(pc, cfg)
	if err := bindToDevice(pc, cfg.Iface); err != nil {
		_ = pc.Close()
		return nil, nil, err
	}
	l := &ipxLinkListener{p: p, pc: pc, cipher: cipher, tunnel: cfg.TunnelPort, log: log,
		mismatch: logx.NewSuppressor(2*time.Minute, 32),
		flows:    map[ipxKey]*ipxFlow{}, accept: make(chan *ipxFlow, 64), closed: make(chan struct{})}
	go l.route()
	return nil, l, nil
}

// listenAddrFor binds the raw socket to one local address when the config names
// one. A server with several addresses otherwise receives this protocol on all
// of them, which is more traffic to filter and, on a box that also runs a real
// GRE or IP-in-IP tunnel, traffic that is not ours at all.
func listenAddrFor(cfg *config.Config) string {
	if a := cfg.ListenIP; a != "" {
		return a
	}
	return ""
}

// tuneRawSocket sizes the socket's buffers. See tuneICMPSocket: a datagram
// socket has no autotuning, and a burst larger than the receive queue is
// discarded by the kernel before this process sees it — loss the tunnel creates
// for itself, on a carrier chosen because the path is already difficult.
func tuneRawSocket(pc net.PacketConn, cfg *config.Config) {
	snd, rcv := nettune.BufSizes(cfg.Profile, cfg.SoSndbuf, cfg.SoRcvbuf)
	type bufConn interface {
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	}
	if c, ok := pc.(bufConn); ok {
		_ = c.SetReadBuffer(rcv)
		_ = c.SetWriteBuffer(snd)
	}
}

// ---- dialer ----------------------------------------------------------------

type ipxLinkDialer struct {
	p      ipxProfile
	peer   string
	cipher string
	cfg    *config.Config
	tunnel int
	log    *logx.Logger

	mu       sync.Mutex
	pc       net.PacketConn
	peerAddr net.Addr
	conns    map[uint16]*ipxConn
	dead     chan struct{}
	deadOnce sync.Once
	announce sync.Once
}

func (d *ipxLinkDialer) socket() (net.PacketConn, net.Addr, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pc != nil {
		return d.pc, d.peerAddr, nil
	}
	pc, err := net.ListenPacket(d.p.network, listenAddrFor(d.cfg))
	if err != nil {
		return nil, nil, fmt.Errorf("%s socket: %w (needs CAP_NET_RAW)", d.p.label, err)
	}
	tuneRawSocket(pc, d.cfg)
	if err := bindToDevice(pc, d.cfg.Iface); err != nil {
		_ = pc.Close()
		return nil, nil, err
	}
	peer, err := net.ResolveIPAddr("ip4", d.peer)
	if err != nil {
		_ = pc.Close()
		return nil, nil, fmt.Errorf("peer %q has no IPv4 address (%w)", d.peer, err)
	}
	d.pc, d.peerAddr = pc, peer
	d.conns = map[uint16]*ipxConn{}
	d.dead = make(chan struct{})
	go d.route()
	return pc, peer, nil
}

func (d *ipxLinkDialer) route() {
	buf := make([]byte, 64*1024)
	for {
		n, _, err := d.pc.ReadFrom(buf)
		if err != nil {
			if isClosed(d.dead) || !isTransientReadErr(err) {
				return
			}
			continue
		}
		payload, link, ok := parseIPX(d.p, buf[:n], dirToDialer, d.tunnel)
		if !ok {
			continue
		}
		d.mu.Lock()
		c := d.conns[uint16(link)]
		d.mu.Unlock()
		if c == nil {
			continue
		}
		bp := getDgram(payload)
		select {
		case c.in <- bp:
		case <-c.closed:
			putDgram(bp)
		default:
			carrierDropped.Add(1)
			putDgram(bp)
		}
	}
}

func (d *ipxLinkDialer) register(c *ipxConn) {
	d.mu.Lock()
	d.conns[uint16(c.link)] = c
	d.mu.Unlock()
}

func (d *ipxLinkDialer) unregister(link int) {
	d.mu.Lock()
	if d.conns != nil {
		delete(d.conns, uint16(link))
	}
	d.mu.Unlock()
}

// freeLinkID picks an id no live link is using. Two links sharing one would read
// each other's frames, which is the only thing this carrier demultiplexes by.
func (d *ipxLinkDialer) freeLinkID() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := 0; i < 64; i++ {
		id := rand.Intn(0xfffe) + 1
		if _, taken := d.conns[uint16(id)]; !taken {
			return id
		}
	}
	for id := 1; id < 0xffff; id++ {
		if _, taken := d.conns[uint16(id)]; !taken {
			return id
		}
	}
	return 1
}

func (d *ipxLinkDialer) DialLink(_ context.Context) (link, error) {
	pc, peer, err := d.socket()
	if err != nil {
		return nil, err
	}
	conn := &ipxConn{d: d, p: d.p, pc: pc, peer: peer,
		link: d.freeLinkID(), tunnel: d.tunnel,
		in: make(chan *[]byte, flowDepth), closed: make(chan struct{})}
	d.register(conn)
	dg, err := crypto.ClientHandshakePacket(conn, d.cipher)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if d.log != nil {
		d.announce.Do(func() {
			d.log.Info("%s carrier up: frames ride in IP protocol %s", d.p.label, d.p.network[4:])
		})
	}
	return newDatagramLink(conn, dg), nil
}

func (d *ipxLinkDialer) Close() error {
	d.mu.Lock()
	pc, dead := d.pc, d.dead
	d.mu.Unlock()
	if dead != nil {
		d.deadOnce.Do(func() { close(dead) })
	}
	if pc != nil {
		return pc.Close()
	}
	return nil
}

// ipxConn is one client-side link presented as a net.Conn. Frames arrive from
// the dialer's shared read loop, keyed by link id.
type ipxConn struct {
	d      *ipxLinkDialer
	p      ipxProfile
	pc     net.PacketConn
	peer   net.Addr
	link   int
	tunnel int

	in     chan *[]byte
	closed chan struct{}
	once   sync.Once
	dg     deadlineGate

	mu      sync.Mutex
	scratch []byte
}

func (c *ipxConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.scratch = appendIPX(c.scratch[:0], c.p, dirToListener, c.tunnel, c.link, b)
	out := c.scratch
	c.mu.Unlock()
	if _, err := c.pc.WriteTo(out, c.peer); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *ipxConn) Read(b []byte) (int, error) {
	bp, err := c.dg.wait(c.in, c.closed)
	if err != nil {
		return 0, err
	}
	n := copy(b, *bp)
	putDgram(bp)
	return n, nil
}

// Close ends this link only; the socket belongs to the dialer and stays open
// for the rest of the pool.
func (c *ipxConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		if c.d != nil {
			c.d.unregister(c.link)
		}
	})
	return nil
}

func (c *ipxConn) SetReadDeadline(t time.Time) error  { c.dg.set(t); return nil }
func (c *ipxConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *ipxConn) SetDeadline(t time.Time) error      { return c.SetReadDeadline(t) }
func (c *ipxConn) LocalAddr() net.Addr                { return c.pc.LocalAddr() }
func (c *ipxConn) RemoteAddr() net.Addr               { return c.peer }

// ---- listener --------------------------------------------------------------

// ipxKey identifies a link by peer address and link id. It is built for every
// packet the server receives, so it must not allocate.
type ipxKey struct {
	addr netip.Addr
	link uint16
}

func makeIPXKey(src net.Addr, link int) (ipxKey, bool) {
	ipa, ok := src.(*net.IPAddr)
	if !ok {
		return ipxKey{}, false
	}
	a, ok := netip.AddrFromSlice(ipa.IP)
	if !ok {
		return ipxKey{}, false
	}
	return ipxKey{addr: a.Unmap(), link: uint16(link)}, true
}

type ipxLinkListener struct {
	p      ipxProfile
	pc     net.PacketConn
	cipher string
	tunnel int
	log    *logx.Logger

	mismatch *logx.Suppressor

	mu    sync.Mutex
	flows map[ipxKey]*ipxFlow

	accept    chan *ipxFlow
	closeOnce sync.Once
	closed    chan struct{}

	once sync.Once
	q    *handshakeQueue
}

func (l *ipxLinkListener) route() {
	buf := make([]byte, 64*1024)
	for {
		n, src, err := l.pc.ReadFrom(buf)
		if err != nil {
			if isClosed(l.closed) || !isTransientReadErr(err) {
				l.Close()
				return
			}
			continue
		}
		payload, linkID, ok := parseIPX(l.p, buf[:n], dirToListener, l.tunnel)
		if !ok {
			l.reportMismatch(src, buf[:n])
			continue
		}
		key, ok := makeIPXKey(src, linkID)
		if !ok {
			continue
		}
		l.mu.Lock()
		f := l.flows[key]
		l.mu.Unlock()
		if f == nil {
			first := append([]byte(nil), payload...)
			f = &ipxFlow{l: l, src: src, link: linkID, key: key,
				in: make(chan *[]byte, flowDepth), firstMsg: first, closed: make(chan struct{})}
			l.mu.Lock()
			l.flows[key] = f
			l.mu.Unlock()
			select {
			case l.accept <- f:
			default:
				l.remove(key)
			}
			continue
		}
		bp := getDgram(payload)
		select {
		case f.in <- bp:
		case <-f.closed:
			putDgram(bp)
		default:
			carrierDropped.Add(1)
			putDgram(bp)
		}
	}
}

// reportMismatch explains a packet that is ours in shape but belongs to another
// tunnel port. Somebody else's real GRE or IP-in-IP says nothing worth logging;
// a peer configured with the wrong tunnel_port produces the same silence and
// means the tunnel will never come up, so that one is named.
func (l *ipxLinkListener) reportMismatch(src net.Addr, raw []byte) {
	if l.log == nil || len(raw) < l.p.prefix+ipxHdr {
		return
	}
	b := raw[l.p.prefix:]
	if b[0] != dirToListener {
		return
	}
	theirs := int(b[1])<<8 | int(b[2])
	if theirs == l.tunnel&0xffff {
		return
	}
	if ok, n := l.mismatch.Allow(src.String()); ok {
		extra := ""
		if n > 0 {
			extra = fmt.Sprintf(" (and %d more since)", n)
		}
		l.log.Warn("%s: frames from %s are for tunnel_port %d, this tunnel is %d — "+
			"set the same tunnel_port on both servers%s", l.p.label, src, theirs, l.tunnel, extra)
	}
}

func (l *ipxLinkListener) remove(key ipxKey) {
	l.mu.Lock()
	delete(l.flows, key)
	l.mu.Unlock()
}

func (l *ipxLinkListener) AcceptLink() (link, error) {
	l.once.Do(func() { ensureQueue(&l.q); l.start() })
	return l.q.next()
}

func (l *ipxLinkListener) start() {
	go func() {
		for {
			select {
			case f := <-l.accept:
				l.q.submit(func() (link, error) {
					dg, err := crypto.ServerHandshakePacket(f, l.cipher, f.firstMsg)
					if err != nil {
						f.Close()
						return nil, err
					}
					return newDatagramLink(f, dg), nil
				}, func() { f.Close() })
			case <-l.closed:
				l.q.close()
				return
			}
		}
	}()
}

func (l *ipxLinkListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed); _ = l.pc.Close() })
	return nil
}

// ipxFlow is one demultiplexed peer link on the listening side.
type ipxFlow struct {
	l        *ipxLinkListener
	src      net.Addr
	link     int
	key      ipxKey
	in       chan *[]byte
	firstMsg []byte

	wmu     sync.Mutex
	scratch []byte

	dg        deadlineGate
	closeOnce sync.Once
	closed    chan struct{}
}

func (f *ipxFlow) Read(b []byte) (int, error) {
	bp, err := f.dg.wait(f.in, f.closed)
	if err != nil {
		return 0, err
	}
	n := copy(b, *bp)
	putDgram(bp)
	return n, nil
}

func (f *ipxFlow) Write(b []byte) (int, error) {
	f.wmu.Lock()
	f.scratch = appendIPX(f.scratch[:0], f.l.p, dirToDialer, f.l.tunnel, f.link, b)
	out := f.scratch
	f.wmu.Unlock()
	if _, err := f.l.pc.WriteTo(out, f.src); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (f *ipxFlow) Close() error {
	f.closeOnce.Do(func() { close(f.closed); f.l.remove(f.key) })
	return nil
}

func (f *ipxFlow) SetReadDeadline(t time.Time) error  { f.dg.set(t); return nil }
func (f *ipxFlow) SetWriteDeadline(t time.Time) error { return nil }
func (f *ipxFlow) SetDeadline(t time.Time) error      { return f.SetReadDeadline(t) }
func (f *ipxFlow) LocalAddr() net.Addr                { return f.l.pc.LocalAddr() }
func (f *ipxFlow) RemoteAddr() net.Addr               { return f.src }
