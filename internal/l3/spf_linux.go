//go:build linux

// SPF ICMP carrier with source-IP spoofing — BETA.
//
// SPF is a point-to-point tunnel between two servers YOU control. Each side
// sends the encrypted frames inside ICMP echo packets whose IP SOURCE address is
// rewritten to `spoof_src_ip` (obfuscation), routed to the peer's real IP
// (`peer`). Inbound packets are accepted only when their source equals
// `spoof_dst_ip` (the peer's spoofed source) — a strict point-to-point filter,
// so this is a configured tunnel endpoint, not a general spoofing tool.
//
// Requires Linux + CAP_NET_RAW (granted by the systemd unit). NOT runtime-tested
// in CI; validate on a real Linux host before production use.
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
)

func newSPFRawCarrier(cfg *config.Config, isDialer bool, cipher string) (linkDialer, linkListener, error) {
	spoofSrc := net.ParseIP(cfg.SpoofSrcIP).To4()
	spoofDst := net.ParseIP(cfg.SpoofDstIP).To4()
	peer := net.ParseIP(cfg.Peer).To4()
	if spoofSrc == nil || spoofDst == nil || peer == nil {
		return nil, nil, fmt.Errorf("spf: spoof_src_ip, spoof_dst_ip and peer must all be IPv4 addresses")
	}
	if isDialer {
		return &spfLinkDialer{spoofSrc: spoofSrc, spoofDst: spoofDst, peer: peer, cipher: cipher}, nil, nil
	}
	rc, err := openRawICMP()
	if err != nil {
		return nil, nil, err
	}
	l := &spfLinkListener{rc: rc, spoofSrc: spoofSrc, spoofDst: spoofDst, peer: peer, cipher: cipher,
		flows: map[int]*spfFlow{}, accept: make(chan *spfFlow, 64), closed: make(chan struct{})}
	go l.route()
	return nil, l, nil
}

func openRawICMP() (*ipv4.RawConn, error) {
	c, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("spf raw socket: %w (needs CAP_NET_RAW)", err)
	}
	rc, err := ipv4.NewRawConn(c)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return rc, nil
}

// writeEcho crafts an IP+ICMP echo packet with a spoofed source and sends it.
func writeEcho(rc *ipv4.RawConn, spoofSrc, dst net.IP, typ icmp.Type, id, seq int, data []byte) error {
	msg := icmp.Message{Type: typ, Code: 0, Body: &icmp.Echo{ID: id, Seq: seq, Data: data}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	h := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(b),
		TTL:      64,
		Protocol: 1, // ICMP
		Src:      spoofSrc,
		Dst:      dst,
	}
	return rc.WriteTo(h, b, nil)
}

// ---- dialer / client -------------------------------------------------------

type spfLinkDialer struct {
	spoofSrc, spoofDst, peer net.IP
	cipher                   string
}

func (d *spfLinkDialer) DialLink(_ context.Context) (link, error) {
	rc, err := openRawICMP()
	if err != nil {
		return nil, err
	}
	conn := &spfConn{rc: rc, spoofSrc: d.spoofSrc, spoofDst: d.spoofDst, peer: d.peer,
		id: rand.Intn(0xfffe) + 1, echoType: ipv4.ICMPTypeEcho}
	dg, err := crypto.ClientHandshakePacket(conn, d.cipher)
	if err != nil {
		_ = rc.Close()
		return nil, err
	}
	return newDatagramLink(conn, dg), nil
}
func (d *spfLinkDialer) Close() error { return nil }

// spfConn is one client-side SPF flow as a net.Conn.
type spfConn struct {
	rc                       *ipv4.RawConn
	spoofSrc, spoofDst, peer net.IP
	id                       int
	seq                      uint32
	echoType                 icmp.Type
}

func (c *spfConn) Write(b []byte) (int, error) {
	c.seq++
	if err := writeEcho(c.rc, c.spoofSrc, c.peer, c.echoType, c.id, int(c.seq&0xffff), b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *spfConn) Read(b []byte) (int, error) {
	buf := make([]byte, len(b)+128)
	for {
		h, p, _, err := c.rc.ReadFrom(buf)
		if err != nil {
			return 0, err
		}
		if !h.Src.Equal(c.spoofDst) { // strict point-to-point source filter
			continue
		}
		data, ok := parseEchoAny(p, c.id)
		if !ok {
			continue
		}
		return copy(b, data), nil
	}
}

func (c *spfConn) Close() error                       { return c.rc.Close() }
func (c *spfConn) SetReadDeadline(t time.Time) error  { return c.rc.SetReadDeadline(t) }
func (c *spfConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *spfConn) SetDeadline(t time.Time) error      { return c.SetReadDeadline(t) }
func (c *spfConn) LocalAddr() net.Addr                { return &net.IPAddr{IP: c.spoofSrc} }
func (c *spfConn) RemoteAddr() net.Addr               { return &net.IPAddr{IP: c.peer} }

// ---- listener / server -----------------------------------------------------

type spfLinkListener struct {
	rc                       *ipv4.RawConn
	spoofSrc, spoofDst, peer net.IP
	cipher                   string

	mu     sync.Mutex
	flows  map[int]*spfFlow
	accept chan *spfFlow

	closeOnce sync.Once
	closed    chan struct{}
}

func (l *spfLinkListener) route() {
	buf := make([]byte, 64*1024)
	for {
		h, p, _, err := l.rc.ReadFrom(buf)
		if err != nil {
			l.Close()
			return
		}
		if !h.Src.Equal(l.spoofDst) {
			continue
		}
		data, id, ok := parseEchoRequestAny(p)
		if !ok {
			continue
		}
		l.mu.Lock()
		f := l.flows[id]
		l.mu.Unlock()
		pkt := make([]byte, len(data))
		copy(pkt, data)
		if f == nil {
			f = &spfFlow{l: l, id: id, in: make(chan []byte, 256), firstMsg: pkt, closed: make(chan struct{})}
			l.mu.Lock()
			l.flows[id] = f
			l.mu.Unlock()
			select {
			case l.accept <- f:
			default:
				l.remove(id)
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

func (l *spfLinkListener) remove(id int) {
	l.mu.Lock()
	delete(l.flows, id)
	l.mu.Unlock()
}

func (l *spfLinkListener) AcceptLink() (link, error) {
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
			return nil, fmt.Errorf("spf listener closed")
		}
	}
}

func (l *spfLinkListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed); _ = l.rc.Close() })
	return nil
}

type spfFlow struct {
	l        *spfLinkListener
	id       int
	in       chan []byte
	firstMsg []byte
	seq      uint32

	dmu       sync.Mutex
	deadline  time.Time
	closeOnce sync.Once
	closed    chan struct{}
}

func (f *spfFlow) Read(b []byte) (int, error) {
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

func (f *spfFlow) Write(b []byte) (int, error) {
	f.seq++
	if err := writeEcho(f.l.rc, f.l.spoofSrc, f.l.peer, ipv4.ICMPTypeEchoReply, f.id, int(f.seq&0xffff), b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (f *spfFlow) SetReadDeadline(t time.Time) error {
	f.dmu.Lock()
	f.deadline = t
	f.dmu.Unlock()
	return nil
}
func (f *spfFlow) Close() error {
	f.closeOnce.Do(func() { close(f.closed); f.l.remove(f.id) })
	return nil
}
func (f *spfFlow) SetWriteDeadline(t time.Time) error { return nil }
func (f *spfFlow) SetDeadline(t time.Time) error      { return f.SetReadDeadline(t) }
func (f *spfFlow) LocalAddr() net.Addr                { return &net.IPAddr{IP: f.l.spoofSrc} }
func (f *spfFlow) RemoteAddr() net.Addr               { return &net.IPAddr{IP: f.l.peer} }

// parseEchoAny returns the Echo data for either request or reply with the id.
func parseEchoAny(raw []byte, wantID int) ([]byte, bool) {
	m, err := icmp.ParseMessage(1, raw)
	if err != nil {
		return nil, false
	}
	echo, ok := m.Body.(*icmp.Echo)
	if !ok || echo.ID != wantID {
		return nil, false
	}
	return echo.Data, true
}

func parseEchoRequestAny(raw []byte) ([]byte, int, bool) {
	m, err := icmp.ParseMessage(1, raw)
	if err != nil || m.Type != ipv4.ICMPTypeEcho {
		return nil, 0, false
	}
	echo, ok := m.Body.(*icmp.Echo)
	if !ok {
		return nil, 0, false
	}
	return echo.Data, echo.ID, true
}
