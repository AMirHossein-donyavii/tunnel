//go:build linux

// SPF carrier with source-IP spoofing — BETA (both ICMP and TCP profiles).
//
// SPF is a point-to-point tunnel between two servers YOU control. Every
// encrypted frame is sent as a raw IPv4 packet whose SOURCE address is rewritten
// to spoof_src_ip and destination is the peer's real IP (peer). Inbound packets
// are accepted only when their source equals spoof_dst_ip (the peer's spoofed
// source) — a strict point-to-point filter. The inner envelope is chosen by
// spf_profile:
//   - icmp: an ICMP echo (id demultiplexes links)
//   - tcp:  a bare TCP segment  (source port demultiplexes links)
//
// Both use the SAME datagram AEAD, handshake, and link framing; only the L4
// envelope and the spoofed IP header differ.
//
// Requires Linux + CAP_NET_RAW. For the tcp profile the peer kernel will emit a
// RST for the unsolicited segments — drop them so they don't reset the flow:
//
//	iptables -A OUTPUT -p tcp --sport <tunnel_port> --tcp-flags RST RST -j DROP
//
// (both hosts). NOT runtime-tested in CI — validate on a real Linux host.
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
	"golang.org/x/net/ipv4"
)

// ---- carrier construction --------------------------------------------------

func newSPFRawCarrier(cfg *config.Config, isDialer bool, cipher string) (linkDialer, linkListener, error) {
	spoofSrc := net.ParseIP(cfg.SpoofSrcIP).To4()
	spoofDst := net.ParseIP(cfg.SpoofDstIP).To4()
	peer := net.ParseIP(cfg.Peer).To4()
	if spoofSrc == nil || spoofDst == nil || peer == nil {
		return nil, nil, fmt.Errorf("spf: spoof_src_ip, spoof_dst_ip and peer must be IPv4 addresses")
	}
	codec := codecFor(cfg.SpfProfile)
	// Size the raw-socket buffers from the performance profile so bursts aren't
	// dropped by a small default kernel buffer on high-throughput links.
	snd, rcv := nettune.BufSizes(cfg.Profile, cfg.SoSndbuf, cfg.SoRcvbuf)
	if isDialer {
		return &spfLinkDialer{codec: codec, spoofSrc: spoofSrc, spoofDst: spoofDst, peer: peer,
			tunnelPort: cfg.TunnelPort, cipher: cipher, sndbuf: snd, rcvbuf: rcv}, nil, nil
	}
	rc, err := openRawIPv4(codec.network(), snd, rcv)
	if err != nil {
		return nil, nil, err
	}
	l := &spfLinkListener{codec: codec, rc: rc, spoofSrc: spoofSrc, spoofDst: spoofDst, peer: peer,
		tunnelPort: cfg.TunnelPort, cipher: cipher, flows: map[int]*spfFlow{}, accept: make(chan *spfFlow, 64), closed: make(chan struct{})}
	go l.route()
	return nil, l, nil
}

// openRawIPv4 opens an IP_HDRINCL raw socket, sizing its send/recv buffers
// (best-effort) so throughput bursts survive a small default kernel buffer.
func openRawIPv4(network string, snd, rcv int) (*ipv4.RawConn, error) {
	c, err := net.ListenPacket(network, "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("spf raw socket %s: %w (needs CAP_NET_RAW)", network, err)
	}
	if ip, ok := c.(*net.IPConn); ok {
		if rcv > 0 {
			_ = ip.SetReadBuffer(rcv)
		}
		if snd > 0 {
			_ = ip.SetWriteBuffer(snd)
		}
	}
	rc, err := ipv4.NewRawConn(c)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return rc, nil
}

// writeSpoofed wraps L4 bytes in an IP header with a spoofed source and sends it.
func writeSpoofed(rc *ipv4.RawConn, proto int, spoofSrc, dst net.IP, l4 []byte) error {
	h := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(l4),
		TTL:      64,
		Protocol: proto,
		Src:      spoofSrc,
		Dst:      dst,
	}
	return rc.WriteTo(h, l4, nil)
}

// ---- dialer / client -------------------------------------------------------

type spfLinkDialer struct {
	codec                    spfCodec
	spoofSrc, spoofDst, peer net.IP
	tunnelPort               int
	cipher                   string
	sndbuf, rcvbuf           int
}

func (d *spfLinkDialer) DialLink(_ context.Context) (link, error) {
	rc, err := openRawIPv4(d.codec.network(), d.sndbuf, d.rcvbuf)
	if err != nil {
		return nil, err
	}
	conn := &spfConn{codec: d.codec, rc: rc, spoofSrc: d.spoofSrc, spoofDst: d.spoofDst, peer: d.peer,
		tunnelPort: d.tunnelPort, key: rand.Intn(0xfffe) + 1}
	dg, err := crypto.ClientHandshakePacket(conn, d.cipher)
	if err != nil {
		_ = rc.Close()
		return nil, err
	}
	return newDatagramLink(conn, dg), nil
}
func (d *spfLinkDialer) Close() error { return nil }

type spfConn struct {
	codec                    spfCodec
	rc                       *ipv4.RawConn
	spoofSrc, spoofDst, peer net.IP
	tunnelPort, key          int
	seq                      uint32
	rbuf                     []byte // reusable receive buffer (single reader)
}

func (c *spfConn) Write(b []byte) (int, error) {
	c.seq++
	l4, err := c.codec.encode(c.spoofSrc, c.peer, c.key, c.tunnelPort, int(c.seq&0xffff), b, false)
	if err != nil {
		return 0, err
	}
	if err := writeSpoofed(c.rc, c.codec.proto(), c.spoofSrc, c.peer, l4); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *spfConn) Read(b []byte) (int, error) {
	// Reuse a single receive buffer across reads (ReadFrame has one reader), so
	// the hot path allocates nothing. Sized to hold the L4 payload plus headers.
	if cap(c.rbuf) < len(b)+128 {
		c.rbuf = make([]byte, len(b)+128)
	}
	buf := c.rbuf[:len(b)+128]
	for {
		h, p, _, err := c.rc.ReadFrom(buf)
		if err != nil {
			if isTransientReadErr(err) {
				continue // ENOBUFS/EINTR under load: skip, don't cycle the link
			}
			return 0, err
		}
		if !h.Src.Equal(c.spoofDst) { // strict point-to-point source filter
			continue
		}
		data, ok := c.codec.matchClient(p, c.key, c.tunnelPort)
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
	codec                    spfCodec
	rc                       *ipv4.RawConn
	spoofSrc, spoofDst, peer net.IP
	tunnelPort               int
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
			// The listener serves every queue from this ONE raw socket. A
			// transient error (ENOBUFS when the kernel receive buffer overflows
			// under load — more likely on the busier TCP profile — or EINTR) must
			// NOT tear it down, or every link is stranded until a manual Iran
			// restart. Only stop on real closure/shutdown.
			if isClosed(l.closed) || !isTransientReadErr(err) {
				l.Close()
				return
			}
			continue
		}
		if !h.Src.Equal(l.spoofDst) {
			continue
		}
		data, key, ok := l.codec.parseServer(p, l.tunnelPort)
		if !ok {
			continue
		}
		l.mu.Lock()
		f := l.flows[key]
		l.mu.Unlock()
		if f == nil {
			first := append([]byte(nil), data...)
			f = &spfFlow{l: l, key: key, in: make(chan *[]byte, flowDepth), firstMsg: first, closed: make(chan struct{})}
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

func (l *spfLinkListener) remove(key int) {
	l.mu.Lock()
	delete(l.flows, key)
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
	key      int
	in       chan *[]byte
	firstMsg []byte
	seq      uint32

	dg        deadlineGate
	closeOnce sync.Once
	closed    chan struct{}
}

func (f *spfFlow) Read(b []byte) (int, error) {
	bp, err := f.dg.wait(f.in, f.closed)
	if err != nil {
		return 0, err
	}
	n := copy(b, *bp)
	putDgram(bp)
	return n, nil
}

func (f *spfFlow) Write(b []byte) (int, error) {
	f.seq++
	l4, err := f.l.codec.encode(f.l.spoofSrc, f.l.peer, f.key, f.l.tunnelPort, int(f.seq&0xffff), b, true)
	if err != nil {
		return 0, err
	}
	if err := writeSpoofed(f.l.rc, f.l.codec.proto(), f.l.spoofSrc, f.l.peer, l4); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (f *spfFlow) SetReadDeadline(t time.Time) error {
	f.dg.set(t)
	return nil
}
func (f *spfFlow) Close() error {
	f.closeOnce.Do(func() { close(f.closed); f.l.remove(f.key) })
	return nil
}
func (f *spfFlow) SetWriteDeadline(t time.Time) error { return nil }
func (f *spfFlow) SetDeadline(t time.Time) error      { return f.SetReadDeadline(t) }
func (f *spfFlow) LocalAddr() net.Addr                { return &net.IPAddr{IP: f.l.spoofSrc} }
func (f *spfFlow) RemoteAddr() net.Addr               { return &net.IPAddr{IP: f.l.peer} }
