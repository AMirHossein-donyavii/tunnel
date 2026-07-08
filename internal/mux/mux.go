package mux

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
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

	writeHi   chan outFrame
	writeNorm chan outFrame

	pingMu   sync.Mutex
	pings    map[uint32]chan struct{}
	pingSeq  uint32
	lastRTT  int64 // nanoseconds, atomic

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
		conn:      conn,
		client:    client,
		cfg:       cfg,
		streams:   make(map[uint32]*Stream),
		accept:    make(chan *Stream, cfg.AcceptBacklog),
		writeHi:   make(chan outFrame, 256),
		writeNorm: make(chan outFrame, 1024),
		pings:     make(map[uint32]chan struct{}),
		closeCh:   make(chan struct{}),
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
		select {
		case s.writeHi <- outFrame{typ: frameGoAway}:
		default:
		}
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

// queue enqueues a frame for the writer, respecting session shutdown.
func (s *Session) queue(f outFrame, hi bool) error {
	ch := s.writeNorm
	if hi {
		ch = s.writeHi
	}
	select {
	case ch <- f:
		return nil
	case <-s.closeCh:
		if f.pooled {
			putBuf(f.data)
		}
		return s.errOrClosed()
	}
}

func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
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
	scratch := make([]byte, 0, 64*1024)
	for {
		f, ok := s.takeBlocking()
		if !ok {
			return
		}
		scratch = appendFrame(scratch[:0], f)
		for len(scratch) < 60*1024 {
			f2, ok := s.takeNonBlocking()
			if !ok {
				break
			}
			scratch = appendFrame(scratch, f2)
		}
		if _, err := s.conn.Write(scratch); err != nil {
			s.closeWithErr(err)
			return
		}
	}
}

func (s *Session) takeBlocking() (outFrame, bool) {
	// Prefer the high-priority queue.
	select {
	case f := <-s.writeHi:
		return f, true
	default:
	}
	select {
	case f := <-s.writeHi:
		return f, true
	case f := <-s.writeNorm:
		return f, true
	case <-s.closeCh:
		return outFrame{}, false
	}
}

func (s *Session) takeNonBlocking() (outFrame, bool) {
	select {
	case f := <-s.writeHi:
		return f, true
	default:
	}
	select {
	case f := <-s.writeNorm:
		return f, true
	default:
		return outFrame{}, false
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
			data := make([]byte, length)
			if _, err := io.ReadFull(s.conn, data); err != nil {
				s.closeWithErr(err)
				return
			}
			if st := s.getStream(id); st != nil {
				st.deliver(data)
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
				s.removeStream(id)
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
