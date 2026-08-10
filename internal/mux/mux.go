package mux

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emergency-tunnel/et/internal/netq"
)

var (
	// ErrSessionClosed is returned once the session is torn down.
	ErrSessionClosed = errors.New("mux: session closed")
	// ErrStreamClosed is returned on writes to a closed stream.
	ErrStreamClosed = errors.New("mux: stream closed")
	// ErrStreamReset is returned when the peer resets a stream.
	ErrStreamReset = errors.New("mux: stream reset by peer")
)

// bufPool recycles DATA payload copies so the hot path allocates ~nothing.
var bufPool = sync.Pool{New: func() any { b := make([]byte, maxFrame); return &b }}

func getBuf() []byte  { return (*(bufPool.Get().(*[]byte)))[:maxFrame] }
func putBuf(b []byte) { c := b[:cap(b)]; bufPool.Put(&c) }

// outFrame is a frame queued for the single writer goroutine.
type outFrame struct {
	typ, flags uint8
	id         uint32
	ctl        uint32 // length field for control frames (winup increment, goaway code)
	data       []byte // payload (DATA/SYN/PING); nil otherwise
	pooled     bool   // return data to bufPool after writing
}

// Config tunes a session.
type Config struct {
	// KeepAlive sends a PING every interval and tears the session down if a
	// reply does not arrive within KeepAliveTimeout. Zero disables keepalive.
	KeepAlive        time.Duration
	KeepAliveTimeout time.Duration
	// AcceptBacklog bounds queued inbound streams before SYNs are RST'd.
	AcceptBacklog int
	// Window is the initial per-stream receive window in bytes (0 = default). It
	// caps the bandwidth-delay product a single stream can fill; both ends should
	// use the same value. Larger raises single-stream throughput on high-BDP
	// links at the cost of RAM per in-flight (unconsumed) stream.
	Window int
}

// DefaultConfig returns sane defaults.
func DefaultConfig() Config {
	return Config{KeepAlive: 10 * time.Second, KeepAliveTimeout: 25 * time.Second, AcceptBacklog: 256}
}

// Session multiplexes many Streams over one net.Conn.
type Session struct {
	conn   net.Conn
	client bool
	cfg    Config

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32
	goAway  bool
	err     error

	accept chan *Stream

	wq *writeQueue

	// rxBuffered is the total delivered-but-unread bytes across all streams.
	rxBuffered atomic.Int64

	pingMu  sync.Mutex
	pings   map[uint32]chan struct{}
	pingSeq uint32
	lastRTT int64 // nanoseconds, atomic

	closeOnce sync.Once
	closeCh   chan struct{}
}

// Client creates the dialing side of a session (opens odd stream IDs).
func Client(conn net.Conn, cfg Config) *Session { return newSession(conn, true, cfg) }

// Server creates the accepting side of a session (opens even stream IDs).
func Server(conn net.Conn, cfg Config) *Session { return newSession(conn, false, cfg) }

func newSession(conn net.Conn, client bool, cfg Config) *Session {
	if cfg.AcceptBacklog <= 0 {
		cfg.AcceptBacklog = 256
	}
	s := &Session{
		conn:    conn,
		client:  client,
		cfg:     cfg,
		streams: make(map[uint32]*Stream),
		accept:  make(chan *Stream, cfg.AcceptBacklog),
		wq:      newWriteQueue(),
		pings:   make(map[uint32]chan struct{}),
		closeCh: make(chan struct{}),
	}
	s.nextID = 1
	if !client {
		s.nextID = 2
	}
	go s.recvLoop()
	go s.sendLoop()
	if cfg.KeepAlive > 0 {
		go s.keepaliveLoop()
	}
	return s
}

// LastRTT returns the most recent measured round-trip time (0 if none yet).
func (s *Session) LastRTT() time.Duration { return time.Duration(atomic.LoadInt64(&s.lastRTT)) }

// QueuedBytes reports the DATA bytes currently waiting in the egress scheduler
// and the peak seen. A queue that sits near its budget means the carrier is the
// bottleneck and streams are being backpressured — which is the intended
// behaviour, not a fault.
func (s *Session) QueuedBytes() (cur, peak int) { return s.wq.snapshot() }

// NumStreams returns the number of currently open streams.
func (s *Session) NumStreams() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams)
}

// IsClosed reports whether the session is torn down.
func (s *Session) IsClosed() bool {
	select {
	case <-s.closeCh:
		return true
	default:
		return false
	}
}

// Done returns a channel closed when the session is torn down.
func (s *Session) Done() <-chan struct{} { return s.closeCh }

// RemoteAddr returns the peer address of the underlying link (for logging).
func (s *Session) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

// OpenStream opens a new outbound stream. dest is an optional destination hint
// carried in the SYN (e.g. the remote port for reverse forwarding). hi requests
// high-priority scheduling.
func (s *Session) OpenStream(dest []byte, hi bool) (*Stream, error) {
	s.mu.Lock()
	if s.err != nil || s.goAway {
		s.mu.Unlock()
		return nil, s.errOrClosed()
	}
	id := s.nextID
	s.nextID += 2
	st := newStream(id, s, hi)
	s.streams[id] = st
	s.mu.Unlock()

	flags := uint8(0)
	if hi {
		flags = flagPri
	}
	if err := s.queue(outFrame{typ: frameSYN, flags: flags, id: id, data: dest}, hi); err != nil {
		s.removeStream(id)
		return nil, err
	}
	return st, nil
}

// AcceptStream returns the next inbound stream.
func (s *Session) AcceptStream() (*Stream, error) {
	select {
	case st := <-s.accept:
		return st, nil
	case <-s.closeCh:
		return nil, s.errOrClosed()
	}
}

// Ping measures RTT to the peer. It blocks until the reply, timeout, or close.
func (s *Session) Ping(timeout time.Duration) (time.Duration, error) {
	id := atomic.AddUint32(&s.pingSeq, 1)
	ch := make(chan struct{})
	s.pingMu.Lock()
	s.pings[id] = ch
	s.pingMu.Unlock()

	start := time.Now()
	var payload [8]byte
	if err := s.queue(outFrame{typ: framePing, id: id, data: payload[:]}, true); err != nil {
		s.pingMu.Lock()
		delete(s.pings, id)
		s.pingMu.Unlock()
		return 0, err
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-ch:
		rtt := time.Since(start)
		atomic.StoreInt64(&s.lastRTT, int64(rtt))
		return rtt, nil
	case <-t.C:
		s.pingMu.Lock()
		delete(s.pings, id)
		s.pingMu.Unlock()
		return 0, errors.New("mux: ping timeout")
	case <-s.closeCh:
		return 0, s.errOrClosed()
	}
}

// Close tears down the session and all its streams.
func (s *Session) Close() error { return s.closeWithErr(ErrSessionClosed) }

func (s *Session) closeWithErr(cause error) error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		if s.err == nil {
			s.err = cause
		}
		streams := make([]*Stream, 0, len(s.streams))
		for _, st := range s.streams {
			streams = append(streams, st)
		}
		s.mu.Unlock()
		// Best-effort GOAWAY so the peer stops opening streams.
		s.wq.putCtrl(outFrame{typ: frameGoAway})
		close(s.closeCh)
		for _, st := range streams {
			st.setErr(s.err)
		}
		_ = s.conn.Close()
	})
	return nil
}

func (s *Session) errOrClosed() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	return ErrSessionClosed
}

// accountRecv adjusts the session-wide receive accounting and tears the session
// down if a peer has pushed past the ceiling that per-stream flow control is
// supposed to keep it under.
func (s *Session) accountRecv(delta int) {
	if s.rxBuffered.Add(int64(delta)) > maxSessionRecvBuffer {
		s.closeWithErr(errors.New("mux: peer exceeded the session receive buffer ceiling"))
	}
}

// orderedWithData reports whether a frame must stay behind the stream's already
// queued DATA. Only FIN does: it closes the sequence, so letting it overtake
// buffered data would truncate the stream at the receiver. SYN has the opposite
// requirement (it must arrive first, which the control class guarantees), and
// RST is an abort whose whole purpose is to overtake.
func orderedWithData(typ uint8) bool { return typ == frameData || typ == frameFIN }

// queue enqueues a frame for the writer, respecting session shutdown.
//
// Control frames are admitted immediately. DATA frames are admitted only while
// the egress byte budget allows, and otherwise block here — which propagates
// backpressure through Stream.Write to whoever is feeding the stream, instead
// of letting an unbounded backlog build in front of every other stream.
func (s *Session) queue(f outFrame, hi bool) error {
	if f.typ == frameWinUp {
		s.wq.putWinUp(f.id, f.ctl)
		return nil
	}
	if !orderedWithData(f.typ) {
		if !s.wq.putCtrl(f) {
			if f.pooled {
				putBuf(f.data)
			}
			return s.errOrClosed()
		}
		return nil
	}
	for {
		accepted, closed := s.wq.tryPutData(f, hi)
		if accepted {
			return nil
		}
		if closed {
			if f.pooled {
				putBuf(f.data)
			}
			return s.errOrClosed()
		}
		select {
		case <-s.wq.space:
		case <-s.closeCh:
			if f.pooled {
				putBuf(f.data)
			}
			return s.errOrClosed()
		}
	}
}

func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// resetStream removes a stream AND discards whatever it still has queued. Used
// on the abort paths (RST sent or received), where the queued bytes will never
// be wanted and would otherwise hold the shared egress budget until the writer
// drained them.
func (s *Session) resetStream(id uint32) {
	s.removeStream(id)
	s.wq.drop(id)
}

func (s *Session) getStream(id uint32) *Stream {
	s.mu.Lock()
	st := s.streams[id]
	s.mu.Unlock()
	return st
}

// ---- writer -----------------------------------------------------------------

// sendLoop serialises frames to the wire, coalescing whatever is queued into a
// single Write. This yields adaptive batching for free: light load writes one
// frame (low latency), heavy load packs many frames per syscall (throughput).
func (s *Session) sendLoop() {
	// The writer owns the queue's lifetime: it drains whatever is left after the
	// session closes (so a GOAWAY still reaches the peer) and then releases every
	// remaining frame's pooled buffer.
	defer s.wq.close()
	scratch := make([]byte, 0, writeBatch+maxFrame)
	// How much may be coalesced into one write follows the link's measured drain
	// rate. A batch is indivisible once handed to the socket, so on a slow link a
	// large one is pure head-of-line blocking for whatever the scheduler picks
	// next — including the control frames the peer is waiting on.
	budget := netq.New(writeBatch)
	for {
		f, ok := s.takeBlocking()
		if !ok {
			return
		}
		scratch = appendFrame(scratch[:0], f)
		limit := budget.Size()
		for len(scratch) < limit {
			f2, ok := s.wq.take()
			if !ok {
				break
			}
			scratch = appendFrame(scratch, f2)
		}
		n := len(scratch)
		start := time.Now()
		if _, err := s.conn.Write(scratch); err != nil {
			s.closeWithErr(err)
			return
		}
		budget.Add(n, time.Since(start))
	}
}

// takeBlocking returns the next frame, waiting for one if the queue is empty.
func (s *Session) takeBlocking() (outFrame, bool) {
	for {
		if f, ok := s.wq.take(); ok {
			return f, true
		}
		select {
		case <-s.wq.ready:
		case <-s.closeCh:
			// Drain whatever is still queued so a GOAWAY written during shutdown
			// still reaches the peer.
			if f, ok := s.wq.take(); ok {
				return f, true
			}
			return outFrame{}, false
		}
	}
}

func appendFrame(dst []byte, f outFrame) []byte {
	var h header
	ln := f.ctl
	if f.data != nil {
		ln = uint32(len(f.data))
	}
	h.encode(f.typ, f.flags, f.id, ln)
	dst = append(dst, h[:]...)
	if f.data != nil {
		dst = append(dst, f.data...)
		if f.pooled {
			putBuf(f.data)
		}
	}
	return dst
}

// ---- reader -----------------------------------------------------------------

func (s *Session) recvLoop() {
	var h header
	// A single reusable read buffer for DATA payloads: deliver() copies the
	// bytes into the stream's buffer, so we never allocate per frame.
	readBuf := make([]byte, maxFrame)
	for {
		if _, err := io.ReadFull(s.conn, h[:]); err != nil {
			s.closeWithErr(err)
			return
		}
		length := h.length()
		typ := h.typ()
		id := h.id()

		switch typ {
		case frameData:
			if length > maxFrame {
				s.closeWithErr(errors.New("mux: oversized data frame"))
				return
			}
			data := readBuf[:length]
			if _, err := io.ReadFull(s.conn, data); err != nil {
				s.closeWithErr(err)
				return
			}
			if st := s.getStream(id); st != nil {
				st.deliver(data) // copies into the stream buffer
			}
		case frameSYN:
			var dest []byte
			if length > 0 {
				if length > maxFrame {
					s.closeWithErr(errors.New("mux: oversized syn"))
					return
				}
				dest = make([]byte, length)
				if _, err := io.ReadFull(s.conn, dest); err != nil {
					s.closeWithErr(err)
					return
				}
			}
			s.handleSYN(id, h.flags(), dest)
		case frameWinUp:
			if st := s.getStream(id); st != nil {
				st.addSendWindow(int(length))
			}
		case frameFIN:
			if st := s.getStream(id); st != nil {
				st.remoteFIN()
			}
		case frameRST:
			if st := s.getStream(id); st != nil {
				st.setErr(ErrStreamReset)
				s.resetStream(id)
			}
		case framePing:
			var payload [8]byte
			if length == 8 {
				if _, err := io.ReadFull(s.conn, payload[:]); err != nil {
					s.closeWithErr(err)
					return
				}
			}
			if h.flags()&flagAck != 0 {
				s.pingMu.Lock()
				if ch, ok := s.pings[id]; ok {
					delete(s.pings, id)
					close(ch)
				}
				s.pingMu.Unlock()
			} else {
				p := payload
				_ = s.queue(outFrame{typ: framePing, flags: flagAck, id: id, data: p[:]}, true)
			}
		case frameGoAway:
			s.mu.Lock()
			s.goAway = true
			s.mu.Unlock()
		default:
			// Unknown frame: skip its payload to stay in sync.
			if length > 0 {
				if _, err := io.CopyN(io.Discard, s.conn, int64(length)); err != nil {
					s.closeWithErr(err)
					return
				}
			}
		}
	}
}

func (s *Session) handleSYN(id uint32, flags uint8, dest []byte) {
	st := newStream(id, s, flags&flagPri != 0)
	st.dest = dest
	s.mu.Lock()
	if s.err != nil {
		s.mu.Unlock()
		return
	}
	s.streams[id] = st
	s.mu.Unlock()

	select {
	case s.accept <- st:
	default:
		// Backlog full: reject the stream rather than block the reader.
		s.removeStream(id)
		_ = s.queue(outFrame{typ: frameRST, id: id}, true)
	}
}

func (s *Session) keepaliveLoop() {
	t := time.NewTicker(s.cfg.KeepAlive)
	defer t.Stop()
	for {
		select {
		case <-s.closeCh:
			return
		case <-t.C:
			if _, err := s.Ping(s.cfg.KeepAliveTimeout); err != nil {
				s.closeWithErr(err)
				return
			}
		}
	}
}
