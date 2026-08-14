//go:build linux

// ICMP / BIP (ICMPv6) carriers for the TUN engine — BETA.
//
// Each encrypted frame rides in the payload of an ICMP Echo message. This mimics
// ping traffic, which some networks allow when TCP/UDP are filtered. Requires a
// Linux host with CAP_NET_RAW.
//
// Both directions send Echo *Replies*. A kernel answers an Echo Request by
// itself, copying the payload back verbatim, and that copy costs the listening
// server an upload of everything the dialer sends — the tunnel's whole download
// volume, on the server that usually has the smaller uplink. It also arrives at
// the dialer indistinguishable by address and id from a real reply, so a dialer
// that accepts it reads its own ciphertext as peer traffic. Sending replies
// avoids both: no kernel answers an Echo Reply. Nothing in this protocol needs
// requests — the direction tag below, not the ICMP type, says which way a frame
// travels — and a path that drops unsolicited replies is detected at dial time
// and falls back (see icmpLinkDialer.pick).
//
// Each payload carries a one-byte direction tag and the tunnel port. The tag
// rejects a mirrored request on the fallback path and stray ping traffic; the
// tunnel port separates two ICMP tunnels on one host, which otherwise read each
// other's frames because a raw ICMP socket receives every ICMP packet the host
// gets. No sysctl is required and ping keeps working.
//
// This carrier reuses the same datagram AEAD, handshake, and link framing as the
// UDP carrier; only the packet envelope differs.
package l3

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/crypto"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/nettune"
	"golang.org/x/net/icmp"
)

// Direction tags live in icmpframe.go: the SPF icmp profile needs them too.

type icmpProto struct {
	network string // "ip4:icmp" or "ip6:ipv6-icmp"
	v6      bool
}

func protoFor(mode string) icmpProto {
	if mode == config.TunModeBIP {
		return icmpProto{"ip6:ipv6-icmp", true}
	}
	return icmpProto{"ip4:icmp", false}
}

func newICMPCarrier(mode string, cfg *config.Config, isDialer bool, cipher string, log *logx.Logger) (linkDialer, linkListener, error) {
	p := protoFor(mode)
	if isDialer {
		return &icmpLinkDialer{proto: p, peer: cfg.Peer, cipher: cipher, cfg: cfg,
			tunnel: cfg.TunnelPort, log: log,
			shape: shapeFrom(cfg.IcmpType, cfg.IcmpCode)}, nil, nil
	}
	pc, err := icmp.ListenPacket(p.network, "")
	if err != nil {
		return nil, nil, fmt.Errorf("icmp listen (%s): %w (needs CAP_NET_RAW)", p.network, err)
	}
	tuneICMPSocket(pc, cfg)
	if err := bindToDevice(pc, cfg.Iface); err != nil {
		_ = pc.Close()
		return nil, nil, err
	}
	l := &icmpLinkListener{proto: p, pc: pc, cipher: cipher, tunnel: cfg.TunnelPort, log: log,
		shape:    shapeFrom(cfg.IcmpType, cfg.IcmpCode),
		mismatch: logx.NewSuppressor(2*time.Minute, 32),
		flows:    map[icmpKey]*icmpFlow{}, accept: make(chan *icmpFlow, 64), closed: make(chan struct{})}
	go l.route()
	return nil, l, nil
}

// ---- dialer / client conn --------------------------------------------------

type icmpLinkDialer struct {
	proto  icmpProto
	peer   string
	cipher string
	cfg    *config.Config
	// tunnel is the configured tunnel port, which ICMP has no use for and this
	// carrier therefore uses to tell its own traffic from another tunnel's on
	// the same host. See icmpframe.go.
	tunnel int
	log    *logx.Logger
	shape  icmpShape // an explicit ICMP message type, when one is configured

	// One raw socket shared by every link of the pool; see socket().
	mu       sync.Mutex
	pc       *icmp.PacketConn
	peerAddr net.Addr
	conns    map[uint16]*icmpConn
	dead     chan struct{}
	deadOnce sync.Once

	// mode records which ICMP message type reached the peer, so only the first
	// link of the pool pays for finding out. See pick.
	mode atomic.Int32
}

// ICMP message type the dialer sends. See pick.
const (
	icmpModeUnknown = 0
	icmpModeReply   = 1
	icmpModeRequest = 2
)

// pick returns the message types to try, best first.
//
// The dialer used to send Echo Requests, and the listener's kernel answers an
// Echo Request all by itself with the payload copied back verbatim. That is not
// merely the duplicate the direction tag already filters out — it is a full copy
// of everything this side sends, leaving the listening server's uplink carrying
// the tunnel's entire download volume for nothing. On the server that is usually
// the one with the smaller uplink, that alone can saturate it, and the real
// traffic in the other direction then queues behind junk. Measured on this
// build: a 1208-byte Echo Request draws 1208 bytes back, an Echo Reply draws
// nothing.
//
// So frames go out as Echo Replies. Nothing in the protocol needs them to be
// requests — the direction tag, not the ICMP type, is what says which way a
// frame is travelling. The risk is a stateful middlebox that drops an Echo Reply
// it has no matching request for, so the old behaviour remains as a fallback and
// is chosen automatically when the first attempt gets no answer.
func (d *icmpLinkDialer) pick() []bool {
	// An explicit message type says exactly what to send, so there is nothing to
	// probe: reply-versus-request is a property of echo, and this is not echo.
	if d.shape.set {
		return []bool{true}
	}
	switch d.mode.Load() {
	case icmpModeReply:
		return []bool{true}
	case icmpModeRequest:
		return []bool{false}
	default:
		return []bool{true, false}
	}
}

// tuneICMPSocket sizes the raw socket's buffers.
//
// It used to size neither, so the carrier ran on the kernel's default receive
// buffer — a couple of hundred kilobytes. A tunnel does not deliver its traffic
// evenly: it arrives in bursts, and a burst larger than the socket queue is
// discarded by the kernel before this process ever sees it. That is packet loss
// the tunnel creates for itself, and on a carrier chosen precisely because the
// path is difficult it is indistinguishable from the path being at fault.
//
// The receive side is sized generously because a datagram socket has no
// autotuning and an over-large receive queue costs only memory — it cannot
// cause the standing delay an over-large *send* queue does, which is why the
// send side keeps the profile's modest size and the tunnel's own scheduler
// stays the place where queueing happens.
func tuneICMPSocket(pc *icmp.PacketConn, cfg *config.Config) {
	snd, rcv := nettune.BufSizes(cfg.Profile, cfg.SoSndbuf, cfg.SoRcvbuf)
	type bufConn interface {
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	}
	// The v4 and v6 raw sockets are reached through different accessors; using
	// the wrong one silently sizes nothing, which is the failure this whole
	// function exists to remove.
	var inner interface{}
	if p6 := pc.IPv6PacketConn(); p6 != nil {
		inner = p6.PacketConn
	} else if p4 := pc.IPv4PacketConn(); p4 != nil {
		inner = p4.PacketConn
	}
	if c, ok := inner.(bufConn); ok {
		_ = c.SetReadBuffer(rcv)
		_ = c.SetWriteBuffer(snd)
	}
}

// socket returns the dialer's shared raw socket, opening it on first use.
//
// Every link used to open its own. A raw ICMP socket has no port and no filter,
// so the kernel copies every ICMP packet the host receives into every one of
// them: with a pool of four links, four copies of every packet, four wakeups,
// four parses, and three discards — work that scales with the square of the
// pool and lands on a server that is usually one core. One socket, one read
// loop, and a map from echo id to link costs one copy however many links there
// are. The listening side has always worked this way.
func (d *icmpLinkDialer) socket() (*icmp.PacketConn, net.Addr, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pc != nil {
		return d.pc, d.peerAddr, nil
	}
	pc, err := icmp.ListenPacket(d.proto.network, "")
	if err != nil {
		return nil, nil, fmt.Errorf("icmp socket: %w (needs CAP_NET_RAW)", err)
	}
	tuneICMPSocket(pc, d.cfg)
	if err := bindToDevice(pc, d.cfg.Iface); err != nil {
		_ = pc.Close()
		return nil, nil, err
	}
	ipnet := "ip4"
	if d.proto.v6 {
		ipnet = "ip6"
	}
	peer, err := net.ResolveIPAddr(ipnet, d.peer)
	if err != nil {
		_ = pc.Close()
		// The resolver's own wording for "you asked for IPv6 and this is an IPv4
		// address" is "no suitable address found", which reads like a routing or
		// DNS fault and sends people to the firewall. Say what is actually wrong.
		if d.proto.v6 {
			return nil, nil, fmt.Errorf("peer %q has no IPv6 address: tun_mode=bip carries the link inside ICMPv6, so peer must be the other server's IPv6 address — use tun_mode=icmp to carry it over IPv4 (%w)", d.peer, err)
		}
		return nil, nil, fmt.Errorf("peer %q has no IPv4 address (%w)", d.peer, err)
	}
	d.pc, d.peerAddr = pc, peer
	d.conns = map[uint16]*icmpConn{}
	d.dead = make(chan struct{})
	go d.route()
	return pc, peer, nil
}

// route is the dialer's single read loop: one copy of each packet, delivered to
// the link whose echo id it carries.
func (d *icmpLinkDialer) route() {
	buf := make([]byte, 64*1024)
	for {
		n, _, err := d.pc.ReadFrom(buf)
		if err != nil {
			if isClosed(d.dead) || !isTransientReadErr(err) {
				return
			}
			continue
		}
		data, id, ok := parseEchoInbound(buf[:n], d.shape, d.proto.v6, true)
		if !ok {
			continue
		}
		payload, ok := stripTag(data, tagToDialer, d.tunnel)
		if !ok {
			continue // another tunnel's, our own output, or ordinary ping traffic
		}
		d.mu.Lock()
		c := d.conns[uint16(id)]
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
			// The link is not keeping up. Dropping here is what the path would
			// have done anyway, and is far better than stalling the loop and
			// taking every other link down with it.
			carrierDropped.Add(1)
			putDgram(bp)
		}
	}
}

func (d *icmpLinkDialer) register(c *icmpConn) {
	d.mu.Lock()
	d.conns[uint16(c.id)] = c
	d.mu.Unlock()
}

func (d *icmpLinkDialer) unregister(id int) {
	d.mu.Lock()
	if d.conns != nil {
		delete(d.conns, uint16(id))
	}
	d.mu.Unlock()
}

func (d *icmpLinkDialer) DialLink(_ context.Context) (link, error) {
	pc, peer, err := d.socket()
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, reply := range d.pick() {
		conn := &icmpConn{d: d, proto: d.proto, pc: pc, peer: peer, shape: d.shape,
			id: d.freeID(), tunnel: d.tunnel, reply: reply,
			in: make(chan *[]byte, flowDepth), closed: make(chan struct{})}
		d.register(conn)
		dg, err := crypto.ClientHandshakePacket(conn, d.cipher)
		if err == nil {
			if d.mode.CompareAndSwap(icmpModeUnknown, modeFor(reply)) && d.log != nil {
				if reply {
					d.log.Info("icmp: sending Echo Replies — the peer's kernel will not copy our traffic back")
				} else {
					d.log.Warn("icmp: the path did not pass Echo Replies; falling back to Echo Requests. " +
						"The peer's kernel will send a copy of everything we send straight back, " +
						"which costs that server an upload copy of this tunnel's download traffic")
				}
			}
			return newDatagramLink(conn, dg), nil
		}
		conn.Close()
		lastErr = err
	}
	return nil, lastErr
}

// freeID picks an echo id no live link on this dialer is using. Two links
// sharing one would read each other's frames, which is the very thing the
// shared socket demultiplexes by.
func (d *icmpLinkDialer) freeID() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := 0; i < 64; i++ {
		id := rand.Intn(0xfffe) + 1
		if _, taken := d.conns[uint16(id)]; !taken {
			return id
		}
	}
	// 64 collisions in a 65535-wide space means the pool is implausibly large;
	// take the first free id rather than loop forever.
	for id := 1; id < 0xffff; id++ {
		if _, taken := d.conns[uint16(id)]; !taken {
			return id
		}
	}
	return 1
}

func modeFor(reply bool) int32 {
	if reply {
		return icmpModeReply
	}
	return icmpModeRequest
}

func (d *icmpLinkDialer) Close() error {
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

// icmpConn is one client-side ICMP flow presented as a net.Conn. Its frames
// arrive from the dialer's shared read loop, keyed by echo id.
type icmpConn struct {
	d     *icmpLinkDialer
	proto icmpProto
	pc    *icmp.PacketConn
	peer  net.Addr
	id    int
	// tunnel is the configured tunnel port, carried in every frame so this link
	// can tell its own traffic from another ICMP tunnel's on the same host.
	tunnel int
	shape  icmpShape
	// reply sends frames as Echo Replies instead of Echo Requests. See
	// icmpLinkDialer.pick: an Echo Request makes the listener's kernel send the
	// whole payload straight back, which costs that server an upload copy of
	// everything this side sends.
	reply bool

	in     chan *[]byte
	closed chan struct{}
	once   sync.Once
	dg     deadlineGate

	mu      sync.Mutex
	seq     uint32
	scratch []byte
}

func (c *icmpConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.seq++
	c.scratch = appendShaped(c.scratch[:0], c.proto, c.shape, c.reply, c.id, int(c.seq&0xffff), tagToListener, c.tunnel, b)
	out := c.scratch
	c.mu.Unlock()
	if _, err := c.pc.WriteTo(out, c.peer); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *icmpConn) Read(b []byte) (int, error) {
	bp, err := c.dg.wait(c.in, c.closed)
	if err != nil {
		return 0, err
	}
	n := copy(b, *bp)
	putDgram(bp)
	return n, nil
}

// Close ends this link only. The socket belongs to the dialer and stays open
// for the rest of the pool.
func (c *icmpConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		if c.d != nil {
			c.d.unregister(c.id)
		}
	})
	return nil
}

func (c *icmpConn) SetReadDeadline(t time.Time) error {
	c.dg.set(t)
	return nil
}
func (c *icmpConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *icmpConn) SetDeadline(t time.Time) error      { return c.SetReadDeadline(t) }
func (c *icmpConn) LocalAddr() net.Addr                { return c.pc.LocalAddr() }
func (c *icmpConn) RemoteAddr() net.Addr               { return c.peer }

// ---- listener / server -----------------------------------------------------

// icmpKey identifies a flow by peer address and ICMP id.
//
// It used to be built with fmt.Sprintf on every inbound packet — formatting an
// address into a string, twice over, on the single busiest path in the program.
// A comparable struct is the same map lookup with nothing allocated and no
// formatting at all.
type icmpKey struct {
	addr netip.Addr
	id   uint16
}

func makeICMPKey(src net.Addr, id int) (icmpKey, bool) {
	ipa, ok := src.(*net.IPAddr)
	if !ok {
		return icmpKey{}, false
	}
	a, ok := netip.AddrFromSlice(ipa.IP)
	if !ok {
		return icmpKey{}, false
	}
	return icmpKey{addr: a.Unmap(), id: uint16(id)}, true
}

type icmpLinkListener struct {
	proto  icmpProto
	pc     *icmp.PacketConn
	cipher string
	tunnel int // see icmpLinkDialer.tunnel
	log    *logx.Logger
	shape  icmpShape
	// mismatch keeps the "wrong tunnel port" diagnosis to one line per source
	// per window; the peer retries this several times a second.
	mismatch *logx.Suppressor

	mu sync.Mutex
	// See icmpKey: the key is built for every packet the server receives, so it
	// must not allocate.
	flows map[icmpKey]*icmpFlow

	accept    chan *icmpFlow
	closeOnce sync.Once
	closed    chan struct{}

	once sync.Once
	q    *handshakeQueue
}

func (l *icmpLinkListener) route() {
	buf := make([]byte, 64*1024)
	for {
		n, src, err := l.pc.ReadFrom(buf)
		if err != nil {
			// Shared listener socket: survive a transient error rather than
			// stranding every link until a manual restart (see udp/spf route).
			if isClosed(l.closed) || !isTransientReadErr(err) {
				l.Close()
				return
			}
			continue
		}
		data, id, ok := parseEchoAnyShaped(buf[:n], l.shape, l.proto.v6)
		if !ok {
			continue
		}
		// Only frames a dialer addressed to us. This rejects ordinary ping
		// traffic from anywhere on the internet, which would otherwise open a
		// flow per source and be offered to the handshake.
		payload, ok := stripTag(data, tagToListener, l.tunnel)
		if !ok {
			// A frame addressed to a tunnel that is not this one is the normal
			// case on a host running two of them, and is silent. But a peer
			// whose tunnel_port does not match ours produces exactly the same
			// silence, and the tunnel simply never comes up with nothing in the
			// log — so name that one. Also covers a peer on an older core, whose
			// frames have no tunnel port in them at all.
			l.reportMismatch(src, data)
			continue
		}
		data = payload
		key, ok := makeICMPKey(src, id)
		if !ok {
			continue
		}
		l.mu.Lock()
		f := l.flows[key]
		l.mu.Unlock()
		if f == nil {
			first := append([]byte(nil), data...)
			f = &icmpFlow{l: l, src: src, id: id, key: key, in: make(chan *[]byte, flowDepth), firstMsg: first, closed: make(chan struct{})}
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
		bp := getDgram(data)
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

// reportMismatch explains a frame that is tagged as ours but belongs to another
// tunnel port. Frames with no direction tag are ordinary ping traffic and say
// nothing worth logging.
func (l *icmpLinkListener) reportMismatch(src net.Addr, data []byte) {
	if l.log == nil || len(data) < icmpFrameHdr || data[0] != tagToListener {
		return
	}
	theirs := int(data[1])<<8 | int(data[2])
	if ok, n := l.mismatch.Allow(src.String()); ok {
		extra := ""
		if n > 0 {
			extra = fmt.Sprintf(" (and %d more since)", n)
		}
		l.log.Warn("icmp: frames from %s are for tunnel_port %d, this tunnel is %d — "+
			"set the same tunnel_port on both servers, or the peer is on an older core%s",
			src, theirs, l.tunnel, extra)
	}
}

func (l *icmpLinkListener) remove(key icmpKey) {
	l.mu.Lock()
	delete(l.flows, key)
	l.mu.Unlock()
}

func (l *icmpLinkListener) AcceptLink() (link, error) {
	l.once.Do(func() { ensureQueue(&l.q); l.start() })
	return l.q.next()
}

// start drains accepted flows, handshaking each in its own goroutine — see
// handshakeQueue for why this must not happen on the accept path.
func (l *icmpLinkListener) start() {
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

func (l *icmpLinkListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed); _ = l.pc.Close() })
	return nil
}

// icmpFlow is one demultiplexed client, replying with Echo Replies.
type icmpFlow struct {
	l        *icmpLinkListener
	src      net.Addr
	id       int
	key      icmpKey
	in       chan *[]byte
	firstMsg []byte

	wmu     sync.Mutex
	seq     uint32
	scratch []byte

	dg        deadlineGate
	closeOnce sync.Once
	closed    chan struct{}
}

func (f *icmpFlow) Read(b []byte) (int, error) {
	bp, err := f.dg.wait(f.in, f.closed)
	if err != nil {
		return 0, err
	}
	n := copy(b, *bp)
	putDgram(bp)
	return n, nil
}

func (f *icmpFlow) Write(b []byte) (int, error) {
	f.wmu.Lock()
	f.seq++
	f.scratch = appendShaped(f.scratch[:0], f.l.proto, f.l.shape, true, f.id, int(f.seq&0xffff), tagToDialer, f.l.tunnel, b)
	out := f.scratch
	f.wmu.Unlock()
	if _, err := f.l.pc.WriteTo(out, f.src); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (f *icmpFlow) SetReadDeadline(t time.Time) error {
	f.dg.set(t)
	return nil
}
func (f *icmpFlow) Close() error {
	f.closeOnce.Do(func() { close(f.closed); f.l.remove(f.key) })
	return nil
}
func (f *icmpFlow) SetWriteDeadline(t time.Time) error { return nil }
func (f *icmpFlow) SetDeadline(t time.Time) error      { return f.SetReadDeadline(t) }
func (f *icmpFlow) LocalAddr() net.Addr                { return f.l.pc.LocalAddr() }
func (f *icmpFlow) RemoteAddr() net.Addr               { return f.src }

// ---- codec -----------------------------------------------------------------

// parseEchoInbound reads a packet the dialer received: the configured message
// type when one is set, and the reply direction otherwise.
func parseEchoInbound(raw []byte, sh icmpShape, v6, wantReply bool) ([]byte, int, bool) {
	if sh.set {
		return parseEchoAnyShaped(raw, sh, v6)
	}
	return parseEchoMsg(raw, v6, wantReply)
}

// parseEcho returns the echo payload when raw is an echo of the wanted id and
// the wanted direction (reply when wantReply, else request). See icmpframe.go
// for the wire format.
func parseEcho(p icmpProto, raw []byte, wantID int, wantReply bool) ([]byte, bool) {
	payload, id, ok := parseEchoMsg(raw, p.v6, wantReply)
	if !ok || id != wantID {
		return nil, false
	}
	return payload, true
}

// ---- framing ---------------------------------------------------------------

// appendEcho appends a complete ICMP echo *request* — header, direction tag,
// payload — to dst, which the caller reuses across packets.
func appendEcho(dst []byte, p icmpProto, id, seq int, tag byte, tunnel int, payload []byte) []byte {
	return appendTagged(dst, p, false, id, seq, tag, tunnel, payload)
}

// appendReply appends a complete ICMP echo *reply* to dst.
func appendReply(dst []byte, p icmpProto, id, seq int, tag byte, tunnel int, payload []byte) []byte {
	return appendTagged(dst, p, true, id, seq, tag, tunnel, payload)
}

func appendTagged(dst []byte, p icmpProto, reply bool, id, seq int, tag byte, tunnel int, payload []byte) []byte {
	return appendShaped(dst, p, icmpShape{}, reply, id, seq, tag, tunnel, payload)
}

// appendShaped is appendTagged with an explicit ICMP message type. See
// icmpShape: left unset the direction's echo type is used, which is what every
// path but a deliberately configured one wants.
func appendShaped(dst []byte, p icmpProto, sh icmpShape, reply bool, id, seq int, tag byte, tunnel int, payload []byte) []byte {
	off := len(dst)
	dst = appendEchoHeaderShaped(dst, sh, p.v6, reply, id, seq)
	dst = appendTag(dst, tag, tunnel)
	dst = append(dst, payload...)
	finishICMP(dst[off:], p.v6)
	return dst
}
