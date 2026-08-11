//go:build linux

// ICMP / BIP (ICMPv6) carriers for the TUN engine — BETA.
//
// Each encrypted frame rides in the payload of an ICMP Echo message: the dialer
// sends Echo Requests, the listener answers with Echo Replies carrying its own
// frames. This mimics ping traffic, which some networks allow when TCP/UDP are
// filtered. Requires a Linux host with CAP_NET_RAW.
//
// The listener's kernel answers echo requests too, and its automatic reply
// carries our own payload back verbatim with the same ICMP id — indistinguishable
// from a real reply by address and id alone. A dialer that accepts those reads
// its own ciphertext as if it came from the peer, and the link passes no traffic
// at all until it times out and cycles. Disabling kernel replies host-wide
// (net.ipv4.icmp_echo_ignore_all=1) does avoid it, but at the price of the server
// no longer answering ping on any interface — including its tunnel address.
//
// So each payload carries a one-byte direction tag instead. A mirrored request
// arrives tagged as a request and is discarded; only genuine peer traffic is
// read. No sysctl is required and ping keeps working.
//
// This carrier reuses the same datagram AEAD, handshake, and link framing as the
// UDP carrier; only the packet envelope differs.
package l3

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/crypto"
	"github.com/emergency-tunnel/et/internal/nettune"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Direction tags. The first payload byte says which way a datagram is
// travelling, so a packet that comes back to its own sender — a kernel echo
// reply mirroring our request — is recognisable and dropped.
const (
	tagToListener = 0xE1 // dialer -> listener, rides in Echo Requests
	tagToDialer   = 0xE2 // listener -> dialer, rides in Echo Replies
)

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

func newICMPCarrier(mode string, cfg *config.Config, isDialer bool, cipher string) (linkDialer, linkListener, error) {
	p := protoFor(mode)
	if isDialer {
		return &icmpLinkDialer{proto: p, peer: cfg.Peer, cipher: cipher, cfg: cfg}, nil, nil
	}
	pc, err := icmp.ListenPacket(p.network, "")
	if err != nil {
		return nil, nil, fmt.Errorf("icmp listen (%s): %w (needs CAP_NET_RAW)", p.network, err)
	}
	tuneICMPSocket(pc, cfg)
	l := &icmpLinkListener{proto: p, pc: pc, cipher: cipher, flows: map[string]*icmpFlow{}, accept: make(chan *icmpFlow, 64), closed: make(chan struct{})}
	go l.route()
	return nil, l, nil
}

// ---- dialer / client conn --------------------------------------------------

type icmpLinkDialer struct {
	proto  icmpProto
	peer   string
	cipher string
	cfg    *config.Config
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

func (d *icmpLinkDialer) DialLink(_ context.Context) (link, error) {
	pc, err := icmp.ListenPacket(d.proto.network, "")
	if err != nil {
		return nil, fmt.Errorf("icmp socket: %w (needs CAP_NET_RAW)", err)
	}
	tuneICMPSocket(pc, d.cfg)
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
			return nil, fmt.Errorf("peer %q has no IPv6 address: tun_mode=bip carries the link inside ICMPv6, so peer must be the other server's IPv6 address — use tun_mode=icmp to carry it over IPv4 (%w)", d.peer, err)
		}
		return nil, fmt.Errorf("peer %q has no IPv4 address (%w)", d.peer, err)
	}
	conn := &icmpConn{proto: d.proto, pc: pc, peer: peer, id: rand.Intn(0xfffe) + 1}
	dg, err := crypto.ClientHandshakePacket(conn, d.cipher)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return newDatagramLink(conn, dg), nil
}

func (d *icmpLinkDialer) Close() error { return nil }

// icmpConn is one client-side ICMP flow presented as a net.Conn.
type icmpConn struct {
	proto icmpProto
	pc    *icmp.PacketConn
	peer  net.Addr
	id    int

	mu      sync.Mutex
	seq     uint32
	scratch []byte
	rbuf    []byte // receive buffer, owned by the single reader
}

func (c *icmpConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.seq++
	c.scratch = appendEcho(c.scratch[:0], c.proto, c.id, int(c.seq&0xffff), tagToListener, b)
	out := c.scratch
	c.mu.Unlock()
	if _, err := c.pc.WriteTo(out, c.peer); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *icmpConn) Read(b []byte) (int, error) {
	// One reader per connection (the datagram link pumps it), so a buffer owned
	// by the conn is safe and removes an allocation from every packet — which on
	// a single-core server is a measurable share of the CPU that could have been
	// spent moving bytes.
	if cap(c.rbuf) < len(b)+64 {
		c.rbuf = make([]byte, len(b)+64)
	}
	buf := c.rbuf[:len(b)+64]
	for {
		n, _, err := c.pc.ReadFrom(buf)
		if err != nil {
			if isTransientReadErr(err) {
				continue // transient under load: skip, don't cycle the link
			}
			return 0, err
		}
		data, ok := parseEcho(c.proto, buf[:n], c.id, true)
		if !ok {
			continue
		}
		// Drop anything tagged for the listener: that is our own request
		// mirrored back by the peer's kernel, not a frame from the peer.
		payload, ok := stripTag(data, tagToDialer)
		if !ok {
			continue
		}
		return copy(b, payload), nil
	}
}

func (c *icmpConn) Close() error                       { return c.pc.Close() }
func (c *icmpConn) SetReadDeadline(t time.Time) error  { return c.pc.SetReadDeadline(t) }
func (c *icmpConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *icmpConn) SetDeadline(t time.Time) error      { return c.SetReadDeadline(t) }
func (c *icmpConn) LocalAddr() net.Addr                { return c.pc.LocalAddr() }
func (c *icmpConn) RemoteAddr() net.Addr               { return c.peer }

// ---- listener / server -----------------------------------------------------

type icmpLinkListener struct {
	proto  icmpProto
	pc     *icmp.PacketConn
	cipher string

	mu    sync.Mutex
	flows map[string]*icmpFlow

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
		data, id, ok := parseEchoRequest(l.proto, buf[:n])
		if !ok {
			continue
		}
		// Only frames a dialer addressed to us. This rejects ordinary ping
		// traffic from anywhere on the internet, which would otherwise open a
		// flow per source and be offered to the handshake.
		data, ok = stripTag(data, tagToListener)
		if !ok {
			continue
		}
		key := fmt.Sprintf("%s/%d", src.String(), id)
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
			putDgram(bp)
		}
	}
}

func (l *icmpLinkListener) remove(key string) {
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
	key      string
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
	f.scratch = appendReply(f.scratch[:0], f.l.proto, f.id, int(f.seq&0xffff), tagToDialer, b)
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

// stripTag accepts a payload only when it carries the expected direction tag,
// and returns it with the tag removed. Traffic travelling the other way — our
// own request mirrored back by a kernel echo reply, or a stray ping from a
// stranger — fails here instead of reaching the AEAD as a peer frame.
func stripTag(data []byte, want byte) ([]byte, bool) {
	if len(data) < 1 || data[0] != want {
		return nil, false
	}
	return data[1:], true
}

// The echo header is a fixed eight bytes — type, code, two checksum bytes, then
// id and seq as big-endian uint16s — with the payload immediately after. The
// receive socket hands us the ICMP message with no IP header in front (that is
// why icmp.ParseMessage worked on the same bytes: it reads offset 0 as the ICMP
// type). Parsing those eight bytes by hand keeps the icmp.Message and
// icmp.Echo allocation that ParseMessage makes off every received packet, which
// on a single-core server is CPU that could have moved bytes instead. The
// checksum is not verified here — the kernel already dropped anything corrupt,
// and the AEAD rejects anything the kernel let through.
const icmpEchoHdr = 8

// parseEcho returns the echo payload when raw is an echo of the wanted id and
// the wanted direction (reply when wantReply, else request).
func parseEcho(p icmpProto, raw []byte, wantID int, wantReply bool) ([]byte, bool) {
	if len(raw) < icmpEchoHdr {
		return nil, false
	}
	if raw[0] != echoTypeByte(p, wantReply) {
		return nil, false
	}
	if int(raw[4])<<8|int(raw[5]) != wantID {
		return nil, false
	}
	return raw[icmpEchoHdr:], true
}

func parseEchoRequest(p icmpProto, raw []byte) ([]byte, int, bool) {
	if len(raw) < icmpEchoHdr {
		return nil, 0, false
	}
	if raw[0] != echoTypeByte(p, false) {
		return nil, 0, false
	}
	id := int(raw[4])<<8 | int(raw[5])
	return raw[icmpEchoHdr:], id, true
}

// ---- framing ---------------------------------------------------------------
//
// The echo header is eight bytes and never varies, so it is written directly
// into a buffer the caller reuses. Building it through icmp.Message.Marshal
// allocated a fresh slice for every packet — tens of thousands per second at
// these rates, and on a one-core server that allocation and the collection it
// causes come straight out of the budget for moving bytes.

// appendEcho appends a complete ICMP echo *request* to dst.
func appendEcho(dst []byte, p icmpProto, id, seq int, tag byte, payload []byte) []byte {
	return appendICMP(dst, echoTypeByte(p, false), id, seq, tag, payload, p.v6)
}

// appendReply appends a complete ICMP echo *reply* to dst.
func appendReply(dst []byte, p icmpProto, id, seq int, tag byte, payload []byte) []byte {
	return appendICMP(dst, echoTypeByte(p, true), id, seq, tag, payload, p.v6)
}

func echoTypeByte(p icmpProto, reply bool) byte {
	if reply {
		if p.v6 {
			return byte(ipv6.ICMPTypeEchoReply)
		}
		return byte(ipv4.ICMPTypeEchoReply)
	}
	if p.v6 {
		return byte(ipv6.ICMPTypeEchoRequest)
	}
	return byte(ipv4.ICMPTypeEcho)
}

func appendICMP(dst []byte, typ byte, id, seq int, tag byte, payload []byte, v6 bool) []byte {
	dst = append(dst, typ, 0, 0, 0) // type, code, checksum placeholder
	dst = append(dst, byte(id>>8), byte(id), byte(seq>>8), byte(seq))
	dst = append(dst, tag)
	dst = append(dst, payload...)
	if !v6 {
		// ICMPv6 checksums cover a pseudo-header the kernel fills in for a raw
		// socket, so leaving it zero there is not just allowed but required.
		ck := checksum(dst)
		dst[2], dst[3] = byte(ck>>8), byte(ck)
	}
	return dst
}

// checksum is the standard one's-complement sum used by ICMPv4. Unlike UDP,
// whose checksum the kernel (often the NIC) computes, a raw ICMP socket leaves
// it to us, so this runs over every byte of every packet sent — it is the one
// per-packet cost the ICMP carrier pays and the UDP carrier does not. It folds
// four bytes per iteration to keep that cost as low as the arithmetic allows;
// the deferred carries cannot overflow uint64 within one datagram.
func checksum(b []byte) uint16 {
	var sum uint64
	for len(b) >= 4 {
		sum += uint64(b[0])<<8 | uint64(b[1])
		sum += uint64(b[2])<<8 | uint64(b[3])
		b = b[4:]
	}
	for len(b) >= 2 {
		sum += uint64(b[0])<<8 | uint64(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint64(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
