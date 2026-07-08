//go:build linux

// ICMP / BIP (ICMPv6) carriers for the TUN engine — BETA.
//
// Each encrypted frame rides in the payload of an ICMP Echo message: the dialer
// sends Echo Requests, the listener answers with Echo Replies carrying its own
// frames. This mimics ping traffic, which some networks allow when TCP/UDP are
// filtered. Requires a Linux host with CAP_NET_RAW, and on the listener:
//
//	sysctl -w net.ipv4.icmp_echo_ignore_all=1     # icmp mode  (or icmpv6.* for bip)
//
// so the kernel does not also auto-reply to the dialer's echo requests.
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
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type icmpProto struct {
	network   string // "ip4:icmp" or "ip6:ipv6-icmp"
	echoType  icmp.Type
	replyType icmp.Type
	protoNum  int // 1 (ICMPv4) or 58 (ICMPv6)
	v6        bool
}

func protoFor(mode string) icmpProto {
	if mode == config.TunModeBIP {
		return icmpProto{"ip6:ipv6-icmp", ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply, 58, true}
	}
	return icmpProto{"ip4:icmp", ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply, 1, false}
}

func newICMPCarrier(mode string, cfg *config.Config, isDialer bool, cipher string) (linkDialer, linkListener, error) {
	p := protoFor(mode)
	if isDialer {
		return &icmpLinkDialer{proto: p, peer: cfg.Peer, cipher: cipher}, nil, nil
	}
	pc, err := icmp.ListenPacket(p.network, "")
	if err != nil {
		return nil, nil, fmt.Errorf("icmp listen (%s): %w (needs CAP_NET_RAW)", p.network, err)
	}
	l := &icmpLinkListener{proto: p, pc: pc, cipher: cipher, flows: map[string]*icmpFlow{}, accept: make(chan *icmpFlow, 64), closed: make(chan struct{})}
	go l.route()
	return nil, l, nil
}

// ---- dialer / client conn --------------------------------------------------

type icmpLinkDialer struct {
	proto  icmpProto
	peer   string
	cipher string
}

func (d *icmpLinkDialer) DialLink(_ context.Context) (link, error) {
	pc, err := icmp.ListenPacket(d.proto.network, "")
	if err != nil {
		return nil, fmt.Errorf("icmp socket: %w (needs CAP_NET_RAW)", err)
	}
	ipnet := "ip4"
	if d.proto.v6 {
		ipnet = "ip6"
	}
	peer, err := net.ResolveIPAddr(ipnet, d.peer)
	if err != nil {
		_ = pc.Close()
		return nil, err
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
	seq   uint32
}

func (c *icmpConn) Write(b []byte) (int, error) {
	c.seq++
	m := icmp.Message{Type: c.proto.echoType, Code: 0,
		Body: &icmp.Echo{ID: c.id, Seq: int(c.seq & 0xffff), Data: b}}
	out, err := m.Marshal(nil)
	if err != nil {
		return 0, err
	}
	if _, err := c.pc.WriteTo(out, c.peer); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *icmpConn) Read(b []byte) (int, error) {
	buf := make([]byte, len(b)+64)
	for {
		n, _, err := c.pc.ReadFrom(buf)
		if err != nil {
			return 0, err
		}
		data, ok := parseEcho(c.proto, buf[:n], c.id, true)
		if !ok {
			continue
		}
		return copy(b, data), nil
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
}

func (l *icmpLinkListener) route() {
	buf := make([]byte, 64*1024)
	for {
		n, src, err := l.pc.ReadFrom(buf)
		if err != nil {
			l.Close()
			return
		}
		data, id, ok := parseEchoRequest(l.proto, buf[:n])
		if !ok {
			continue
		}
		key := fmt.Sprintf("%s/%d", src.String(), id)
		l.mu.Lock()
		f := l.flows[key]
		l.mu.Unlock()
		pkt := make([]byte, len(data))
		copy(pkt, data)
		if f == nil {
			f = &icmpFlow{l: l, src: src, id: id, key: key, in: make(chan []byte, 256), firstMsg: pkt, closed: make(chan struct{})}
			l.mu.Lock()
			l.flows[key] = f
			l.mu.Unlock()
			select {
			case l.accept <- f:
			default:
				l.remove(key)
			}
		} else {
			select {
			case f.in <- pkt:
			case <-f.closed:
			default:
			}
		}
	}
}

func (l *icmpLinkListener) remove(key string) {
	l.mu.Lock()
	delete(l.flows, key)
	l.mu.Unlock()
}

func (l *icmpLinkListener) AcceptLink() (link, error) {
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
			return nil, fmt.Errorf("icmp listener closed")
		}
	}
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
	in       chan []byte
	firstMsg []byte
	seq      uint32

	dmu       sync.Mutex
	deadline  time.Time
	closeOnce sync.Once
	closed    chan struct{}
}

func (f *icmpFlow) Read(b []byte) (int, error) {
	f.dmu.Lock()
	dl := f.deadline
	f.dmu.Unlock()
	var timeout <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, timeoutErr{}
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timeout = t.C
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

func (f *icmpFlow) Write(b []byte) (int, error) {
	f.seq++
	m := icmp.Message{Type: f.l.proto.replyType, Code: 0,
		Body: &icmp.Echo{ID: f.id, Seq: int(f.seq & 0xffff), Data: b}}
	out, err := m.Marshal(nil)
	if err != nil {
		return 0, err
	}
	if _, err := f.l.pc.WriteTo(out, f.src); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (f *icmpFlow) SetReadDeadline(t time.Time) error {
	f.dmu.Lock()
	f.deadline = t
	f.dmu.Unlock()
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

// parseEcho parses an ICMP message and returns the Echo body data if it matches
// the wanted id and (reply?reply:request) type.
func parseEcho(p icmpProto, raw []byte, wantID int, wantReply bool) ([]byte, bool) {
	m, err := icmp.ParseMessage(p.protoNum, raw)
	if err != nil {
		return nil, false
	}
	echo, ok := m.Body.(*icmp.Echo)
	if !ok || echo.ID != wantID {
		return nil, false
	}
	isReply := m.Type == p.replyType
	if isReply != wantReply {
		return nil, false
	}
	return echo.Data, true
}

func parseEchoRequest(p icmpProto, raw []byte) ([]byte, int, bool) {
	m, err := icmp.ParseMessage(p.protoNum, raw)
	if err != nil || m.Type != p.echoType {
		return nil, 0, false
	}
	echo, ok := m.Body.(*icmp.Echo)
	if !ok {
		return nil, 0, false
	}
	return echo.Data, echo.ID, true
}

