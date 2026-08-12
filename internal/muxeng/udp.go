package muxeng

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emergency-tunnel/et/internal/mux"
)

// UDP forwarding.
//
// The mux engine forwarded TCP and nothing else, which quietly decided what
// could be tunnelled through it. OpenVPN, WireGuard, QUIC, game servers and
// voice all run on UDP by preference, and a user who wanted OpenVPN through a
// Backpack transport had only one option left: run OpenVPN in its TCP mode.
//
// That is the worst configuration available. OpenVPN/TCP retransmits lost
// segments, and so does the TCP carrier underneath it, so a single loss is
// recovered twice — the inner timer fires while the outer one is still waiting,
// and each retransmission adds load that causes the next loss. It holds up under
// light traffic and collapses under real use, which is exactly the "works for a
// few minutes then dies and never comes back" that gets blamed on detection.
// Carrying the datagrams as datagrams removes the inner reliability layer
// entirely: a lost packet stays lost, and the user's own TCP — the only layer
// that should be recovering it — does so end to end.
//
// A mux stream is an ordered byte stream, so each datagram is length-prefixed to
// keep its boundaries. Boundaries are the whole point: a UDP protocol that
// receives two datagrams merged, or one split, is receiving corruption.

const (
	// udpMaxDatagram bounds one datagram. Anything larger cannot have arrived on
	// a UDP socket in the first place; the limit exists so a peer cannot make us
	// allocate arbitrarily by claiming a huge length.
	udpMaxDatagram = 65535

	// udpIdleTimeout reaps a client that has stopped sending. UDP has no close,
	// so a session is only ever finished by silence. It is generous because VPN
	// clients legitimately go quiet — a laptop that sleeps for a minute should
	// find its session still there, since losing it means a full renegotiation.
	udpIdleTimeout = 5 * time.Minute

	// protoUDP marks a stream as carrying datagrams. See udpDest.
	protoUDP = 1
)

// udpDest builds the stream header for a UDP forward.
//
// The TCP header is a bare 2-byte port, so there is no spare field to add a
// protocol to. Rather than steal bits from the port, a UDP header opens with a
// port of zero — which is never a valid destination — followed by the protocol
// and the real port. An exit that predates UDP forwarding reads the zero, tries
// to dial port 0, and fails cleanly; it cannot mistake this for a TCP forward
// and deliver the framing bytes to a service as if they were payload.
func udpDest(port int) []byte {
	return []byte{0, 0, protoUDP, byte(port >> 8), byte(port)}
}

// parseDest splits a stream header into its protocol and port. The TCP form
// (a bare port, optionally followed by PROXY-protocol bytes) is unchanged.
func parseDest(dest []byte) (isUDP bool, port int, extra []byte, ok bool) {
	if len(dest) < 2 {
		return false, 0, nil, false
	}
	if binary.BigEndian.Uint16(dest[:2]) != 0 {
		return false, int(binary.BigEndian.Uint16(dest[:2])), dest[2:], true
	}
	if len(dest) < 5 || dest[2] != protoUDP {
		return false, 0, nil, false
	}
	return true, int(dest[3])<<8 | int(dest[4]), nil, true
}

// ---- datagram framing over a stream -----------------------------------------

// writeDatagram writes one length-prefixed datagram.
//
// scratch is the caller's reusable buffer holding the length and the payload
// together, because they must reach the stream as ONE write: split into two,
// another goroutine's write can land between them and the receiver reads our
// length followed by someone else's bytes — a desynchronisation the stream never
// recovers from. Reusing the buffer also keeps an allocation off a path that
// runs once per packet of a VPN session.
func writeDatagram(w io.Writer, scratch *[]byte, p []byte) error {
	if len(p) > udpMaxDatagram {
		return fmt.Errorf("datagram of %d bytes exceeds the %d limit", len(p), udpMaxDatagram)
	}
	need := 2 + len(p)
	if cap(*scratch) < need {
		*scratch = make([]byte, need)
	}
	b := (*scratch)[:need]
	binary.BigEndian.PutUint16(b, uint16(len(p)))
	copy(b[2:], p)
	if _, err := w.Write(b); err != nil {
		return err
	}
	return nil
}

// readDatagram reads one length-prefixed datagram into buf.
func readDatagram(r io.Reader, buf []byte) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > len(buf) {
		return nil, fmt.Errorf("peer announced a %d-byte datagram, larger than the %d buffer", n, len(buf))
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// ---- entry side --------------------------------------------------------------

// udpSession is one client of a forwarded UDP port, bound to its own stream.
type udpSession struct {
	st   *mux.Stream
	last atomic.Int64 // unix nanos of the last datagram from this client
	once sync.Once
}

func (s *udpSession) touch() { s.last.Store(time.Now().UnixNano()) }

// serveUDPForward binds a forwarded UDP port and relays each client's datagrams
// over its own mux stream.
func (e *Engine) serveUDPForward(ctx context.Context, port int, t target) {
	var pc *net.UDPConn
	backoff := time.Second
	warned := false
	for {
		var err error
		pc, err = net.ListenUDP("udp", &net.UDPAddr{Port: port})
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return
		}
		if !warned {
			e.log.Error("cannot bind VPN/listen port udp/%d yet (%v) — clients cannot connect until it is free; retrying", port, err)
			warned = true
		}
		if !sleepCtx(ctx, &backoff) {
			return
		}
	}
	// A VPN's traffic arrives in bursts; a burst larger than the socket queue is
	// dropped before this process sees it, and for a datagram protocol that loss
	// is not recovered anywhere below the user's own transport.
	if e.rcvbuf > 0 {
		_ = pc.SetReadBuffer(e.rcvbuf)
	}

	e.log.Info("mux forwarding udp/%d -> exit udp/%d", port, t.remote)
	atomic.AddInt64(&e.stats.forwardsUp, 1)
	defer atomic.AddInt64(&e.stats.forwardsUp, -1)
	go func() { <-ctx.Done(); _ = pc.Close() }()

	var mu sync.Mutex
	sessions := map[netip.AddrPort]*udpSession{}
	drop := func(key netip.AddrPort, s *udpSession) {
		s.once.Do(func() {
			mu.Lock()
			if sessions[key] == s {
				delete(sessions, key)
			}
			mu.Unlock()
			_ = s.st.Close()
		})
	}
	go e.reapUDP(ctx, &mu, sessions, drop)

	buf := make([]byte, udpMaxDatagram)
	scratch := make([]byte, 0, 2048)
	for {
		n, src, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		mu.Lock()
		s := sessions[src]
		mu.Unlock()

		if s == nil {
			st := e.openStream(ctx, udpDest(t.remote), t.hi)
			if st == nil {
				continue // no session available; the datagram is dropped, as UDP allows
			}
			s = &udpSession{st: st}
			s.touch()
			mu.Lock()
			sessions[src] = s
			mu.Unlock()
			atomic.AddInt64(&e.stats.activeStreams, 1)
			atomic.AddUint64(&e.stats.totalStreams, 1)
			go e.udpReturn(pc, src, s, func() { drop(src, s) })
		}
		s.touch()
		if err := writeDatagram(s.st, &scratch, buf[:n]); err != nil {
			drop(src, s)
		}
	}
}

// udpReturn pumps the exit's datagrams back to one client.
func (e *Engine) udpReturn(pc *net.UDPConn, dst netip.AddrPort, s *udpSession, done func()) {
	defer func() {
		done()
		atomic.AddInt64(&e.stats.activeStreams, -1)
	}()
	buf := make([]byte, udpMaxDatagram)
	for {
		p, err := readDatagram(s.st, buf)
		if err != nil {
			return
		}
		s.touch()
		if _, err := pc.WriteToUDPAddrPort(p, dst); err != nil {
			return
		}
	}
}

// reapUDP closes sessions whose client has gone silent. Without it every client
// that ever sent a packet would hold a stream for the life of the process.
func (e *Engine) reapUDP(ctx context.Context, mu *sync.Mutex, sessions map[netip.AddrPort]*udpSession, drop func(netip.AddrPort, *udpSession)) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cut := time.Now().Add(-udpIdleTimeout).UnixNano()
			var stale []netip.AddrPort
			var vals []*udpSession
			mu.Lock()
			for k, s := range sessions {
				if s.last.Load() < cut {
					stale = append(stale, k)
					vals = append(vals, s)
				}
			}
			mu.Unlock()
			for i := range stale {
				drop(stale[i], vals[i])
			}
		}
	}
}

// openStream opens one stream on any live session, retrying while the tunnel is
// still coming up. Shared with the TCP path's behaviour on purpose: a forward
// that gives up on the first attempt fails every client during a reconnect.
func (e *Engine) openStream(ctx context.Context, dest []byte, hi bool) *mux.Stream {
	deadline := time.Now().Add(openWaitTO)
	for attempt := 0; attempt < openRetry && ctx.Err() == nil; attempt++ {
		sess := e.set.pick()
		if sess == nil {
			if time.Now().After(deadline) {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
			attempt--
			continue
		}
		if st, err := sess.OpenStream(dest, hi); err == nil {
			return st
		}
	}
	return nil
}

// ---- exit side ---------------------------------------------------------------

// serveExitUDP dials the local UDP service and relays datagrams both ways.
func (e *Engine) serveExitUDP(st *mux.Stream, port int) {
	target := net.JoinHostPort(e.exitHost, fmt.Sprintf("%d", port))
	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		e.sessionErr("resolve exit service udp/%s: %v", target, err)
		_ = st.Close()
		return
	}
	pc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		e.sessionErr("dial exit service udp/%s: %v", target, err)
		_ = st.Close()
		return
	}
	if e.rcvbuf > 0 {
		_ = pc.SetReadBuffer(e.rcvbuf)
	}
	atomic.AddInt64(&e.stats.activeStreams, 1)
	atomic.AddUint64(&e.stats.totalStreams, 1)
	defer func() {
		atomic.AddInt64(&e.stats.activeStreams, -1)
		_ = pc.Close()
		_ = st.Close()
	}()

	done := make(chan struct{})
	// Service -> stream.
	go func() {
		defer close(done)
		buf := make([]byte, udpMaxDatagram)
		scratch := make([]byte, 0, 2048)
		for {
			n, err := pc.Read(buf)
			if err != nil {
				return
			}
			if err := writeDatagram(st, &scratch, buf[:n]); err != nil {
				return
			}
		}
	}()
	// Stream -> service.
	buf := make([]byte, udpMaxDatagram)
	for {
		p, err := readDatagram(st, buf)
		if err != nil {
			break
		}
		if _, err := pc.Write(p); err != nil {
			break
		}
	}
	_ = pc.Close()
	<-done
}
