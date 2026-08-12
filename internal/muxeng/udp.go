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

	// udpQueueDepth is how many datagrams may wait for one client while the
	// carrier is busy.
	//
	// It exists because a mux stream blocks its writer once the peer's window is
	// full. Writing straight from the socket loop meant that when the carrier
	// congested, the loop stopped reading — so EVERY client on the port stalled
	// behind whichever one was blocked, and the kernel's receive queue overflowed
	// and discarded the lot. Each client now has its own queue and its own writer,
	// so congestion costs that client and nobody else.
	//
	// Deep enough to ride out a burst, shallow enough that the delay it can add
	// stays small: 64 full-size datagrams is about 90 KB.
	udpQueueDepth = 64

	// udpSafeDatagram is the largest forwarded datagram that still fits inside
	// the tunnel without the outer path having to fragment it.
	//
	// A forwarded datagram travels inside the carrier, which adds its own
	// headers and AEAD overhead on top of the usual IP and TCP or UDP. A VPN
	// left at the default 1500-byte MTU therefore produces packets the outer
	// path must fragment, and a lost fragment destroys the whole datagram — so
	// small packets keep working while large transfers stall, which is what
	// "the tunnel is fine but downloads break" looks like, and reads to most
	// people as detection. It is worth naming precisely once rather than
	// leaving the operator to guess.
	udpSafeDatagram = 1400

	// udpStale is how long a datagram may wait before it is thrown away instead
	// of sent.
	//
	// A VPN datagram has a shelf life. Once it is this late the inner TCP has
	// already decided it was lost and sent another, so delivering it adds load
	// and a duplicate without helping anyone — the same reasoning the TUN
	// scheduler uses for its express class. Dropping is also what the UDP path
	// this replaces would have done, which is the behaviour OpenVPN is built for.
	udpStale = 100 * time.Millisecond

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

// warnOversize keeps the fragmentation warning to one line for the life of the
// process: it is advice about configuration, and repeating it per packet would
// bury the log it is meant to be found in.
var warnOversize sync.Once

// dgram is one queued datagram and the moment it was accepted, so the writer
// can tell whether it is still worth sending.
type dgram struct {
	b   []byte
	enq time.Time
}

// dgramPool recycles datagram buffers. A VPN session is tens of thousands of
// packets a minute; without this each one would allocate.
var dgramPool = sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }}

func takeDgram(p []byte) []byte {
	bp := dgramPool.Get().(*[]byte)
	b := (*bp)[:0]
	if cap(b) < len(p) {
		b = make([]byte, 0, len(p))
	}
	return append(b, p...)
}

func giveDgram(b []byte) {
	if cap(b) <= 1<<16 {
		b = b[:0]
		dgramPool.Put(&b)
	}
}

// udpSession is one client of a forwarded UDP port, bound to its own stream.
//
// out decouples the socket reader from the carrier: the reader never blocks, so
// one congested client cannot stall the others or make the kernel drop the whole
// port's traffic. Overflow drops, which is what the UDP path being replaced here
// would have done anyway.
type udpSession struct {
	// stream is set once the carrier has given us one, which now happens AFTER
	// the session exists — so it is read by the reaper and the teardown path
	// while the opener may still be filling it in.
	stream atomic.Pointer[mux.Stream]
	out    chan dgram
	// closed is how a session ends. The queue itself is NEVER closed.
	//
	// It was, once, and that was a crash: teardown ran on the reaper's goroutine
	// or the return pump's while the socket read loop was still offering
	// datagrams, and a send on a closed channel panics. The tunnel therefore
	// carried traffic normally until the first session ended — an idle client, a
	// stream error — and then the whole process died and took every other tunnel
	// on the server with it. A signal that senders can watch has no such window.
	closed  chan struct{}
	closeOn sync.Once

	last atomic.Int64 // unix nanos of the last datagram from this client
	// dropped counts what congestion cost this client, for the log line that
	// tells an operator the carrier is the limit rather than the tunnel.
	dropped atomic.Uint64
	stale   atomic.Uint64
}

func (s *udpSession) touch() { s.last.Store(time.Now().UnixNano()) }

// shutdown ends the session exactly once.
func (s *udpSession) shutdown() {
	s.closeOn.Do(func() { close(s.closed) })
}

// drain releases whatever is still queued once the session is over, so a
// session that dies mid-burst does not strand its buffers.
func (s *udpSession) drain() {
	for {
		select {
		case d := <-s.out:
			giveDgram(d.b)
		default:
			return
		}
	}
}

// offer queues a datagram without ever blocking. A full queue means the carrier
// cannot keep up; the newest datagram is dropped, exactly as a saturated network
// path would drop it.
func (s *udpSession) offer(p []byte) {
	select {
	case <-s.closed:
		return
	default:
	}
	d := dgram{b: takeDgram(p), enq: time.Now()}
	select {
	case s.out <- d:
	case <-s.closed:
		giveDgram(d.b)
	default:
		giveDgram(d.b)
		s.dropped.Add(1)
	}
}

// pump drains one client's queue into its stream. Stream.Write blocks when the
// peer's window is full, which is precisely why this runs on its own goroutine.
// The stream is passed in rather than read from the session: the caller has just
// opened it, and this way there is no window where it could still be nil.
func (s *udpSession) pump(st *mux.Stream, done func()) {
	defer done()
	scratch := make([]byte, 0, 2048)
	for {
		var d dgram
		select {
		case <-s.closed:
			return
		case d = <-s.out:
		}
		b := d.b
		if time.Since(d.enq) > udpStale {
			// Past its shelf life: sending it now would be a duplicate of
			// something the inner transport already replaced.
			s.stale.Add(1)
			giveDgram(b)
			continue
		}
		err := writeDatagram(st, &scratch, b)
		giveDgram(b)
		if err != nil {
			return
		}
	}
}

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
		select {
		case <-s.closed:
			return // already gone
		default:
		}
		mu.Lock()
		if sessions[key] == s {
			delete(sessions, key)
		}
		mu.Unlock()
		s.shutdown() // signals senders and pumps; never closes the queue
		if st := s.stream.Load(); st != nil {
			_ = st.Close()
		}
		s.drain()
		atomic.AddUint64(&e.stats.udpDropped, s.dropped.Load())
		atomic.AddUint64(&e.stats.udpStale, s.stale.Load())
		if n := s.dropped.Load() + s.stale.Load(); n > 0 {
			e.log.Info("udp/%d: %d datagram(s) dropped for one client — the carrier could not keep up", port, n)
		}
	}
	go e.reapUDP(ctx, &mu, sessions, drop)

	buf := make([]byte, udpMaxDatagram)
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
			// Open the carrier stream OFF this loop.
			//
			// Opening waits for a live session, and while the carrier is down or
			// reconnecting that wait is seconds long. Doing it here meant the
			// socket stopped being read for exactly as long — so a hiccup under
			// load became a total blackout for every client on the port, the
			// kernel discarding everything that arrived meanwhile. A VPN reads
			// that as the path vanishing, which is precisely when it gives up.
			//
			// The session is created immediately instead, and its queue absorbs
			// datagrams while the stream is being established. If it never is,
			// the session is dropped and the queued datagrams are released — the
			// same outcome as before, without stalling everyone else to get it.
			s = &udpSession{out: make(chan dgram, udpQueueDepth), closed: make(chan struct{})}
			s.touch()
			mu.Lock()
			sessions[src] = s
			mu.Unlock()
			ses, key := s, src
			go func() {
				st := e.openStream(ctx, udpDest(t.remote), t.hi)
				if st == nil {
					atomic.AddUint64(&e.stats.udpFailed, 1)
					drop(key, ses)
					return
				}
				atomic.AddUint64(&e.stats.udpOpened, 1)
				ses.stream.Store(st)
				atomic.AddInt64(&e.stats.activeStreams, 1)
				atomic.AddUint64(&e.stats.totalStreams, 1)
				defer atomic.AddInt64(&e.stats.activeStreams, -1)
				go ses.pump(st, func() { drop(key, ses) })
				e.udpReturn(pc, key, ses, st, func() { drop(key, ses) })
			}()
		}
		s.touch()
		atomic.AddUint64(&e.stats.udpIn, 1)
		if n > udpSafeDatagram {
			warnOversize.Do(func() {
				e.log.Warn("udp/%d: this service is sending %d-byte datagrams; anything over %d "+
					"has to be fragmented by the path outside the tunnel, and one lost fragment "+
					"loses the whole packet — which shows up as large transfers stalling while "+
					"small ones work. For OpenVPN set 'tun-mtu 1400' and 'mssfix 1360'.",
					port, n, udpSafeDatagram)
			})
		}
		// Never blocks: see udpSession.offer.
		s.offer(buf[:n])
	}
}

// udpReturn pumps the exit's datagrams back to one client.
func (e *Engine) udpReturn(pc *net.UDPConn, dst netip.AddrPort, s *udpSession, st *mux.Stream, done func()) {
	defer done()
	buf := make([]byte, udpMaxDatagram)
	for {
		p, err := readDatagram(st, buf)
		if err != nil {
			return
		}
		s.touch()
		atomic.AddUint64(&e.stats.udpOut, 1)
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

	// Service -> stream, through the same bounded queue the entry side uses and
	// for the same reason: the stream blocks when the peer's window is full, and
	// a blocked write here would stop this socket being read at all. The return
	// direction is the download, so a stall here is what a user feels most.
	back := &udpSession{out: make(chan dgram, udpQueueDepth), closed: make(chan struct{})}
	back.stream.Store(st)
	pumped := make(chan struct{})
	go func() { defer close(pumped); back.pump(st, func() {}) }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, udpMaxDatagram)
		for {
			n, err := pc.Read(buf)
			if err != nil {
				return
			}
			back.offer(buf[:n])
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
	back.shutdown()
	<-pumped
	if n := back.dropped.Load(); n > 0 {
		e.log.Info("udp/%d: %d datagram(s) dropped on the return path — the carrier could not keep up", port, n)
	}
}
