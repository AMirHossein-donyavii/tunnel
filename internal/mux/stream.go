package mux

import (
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Stream is one logical connection multiplexed over a Session. It satisfies the
// net.Conn-ish contract used by the tunnel (Read/Write/Close plus deadlines are
// approximated by the caller via context, so full net.Conn is not required).
type Stream struct {
	id   uint32
	s    *Session
	hi   bool
	dest []byte // SYN hint (e.g. remote port) for accepted streams

	// receive side
	rmu      sync.Mutex
	rcond    *sync.Cond
	rbuf     []byte // pending, bounded by the receive window via flow control
	rFIN     bool   // peer sent FIN
	consumed int    // bytes consumed since last WINDOW_UPDATE

	// Receive-window auto-tuning. A fixed window caps a single stream at
	// window/RTT no matter how fast the path is: 512 KiB over a 100 ms route is
	// 42 Mbit/s, which is why one upload stream crawls on a link that measures
	// far higher. The window has to follow the path, and the only thing the
	// receiver can see of the path is how quickly it drains what it advertised.
	win      int       // currently advertised receive window
	drained  int       // bytes consumed since lastGrow
	lastGrow time.Time // when the window was last reconsidered

	// send side
	wmu     sync.Mutex
	wcond   *sync.Cond
	sendWin int
	winGrip int  // bytes consumed before a WINDOW_UPDATE is sent (window/2)
	wFIN    bool // we sent FIN

	// shared
	err error
	emu sync.Mutex

	// lifecycle: once both directions are closed the stream is reaped from the
	// session map so long-lived sessions with many short streams don't leak.
	localClosed  atomic.Bool
	remoteClosed atomic.Bool
}

// maybeReap removes the stream from the session once both sides are closed.
func (st *Stream) maybeReap() {
	if st.localClosed.Load() && st.remoteClosed.Load() {
		st.s.removeStream(st.id)
	}
}

func newStream(id uint32, s *Session, hi bool) *Stream {
	// Both ends start with the same initial window (from Config, else the
	// default), so send-side credit matches the peer's receive accounting.
	win := s.cfg.Window
	if win <= 0 {
		win = defaultWindow
	}
	st := &Stream{id: id, s: s, hi: hi, sendWin: win, winGrip: win / 2,
		win: win, lastGrow: time.Now()}
	s.winTotal.Add(int64(win))
	st.rcond = sync.NewCond(&st.rmu)
	st.wcond = sync.NewCond(&st.wmu)
	return st
}

// Dest returns the SYN destination hint (nil for locally-opened streams).
func (st *Stream) Dest() []byte { return st.dest }

// ID returns the stream identifier.
func (st *Stream) ID() uint32 { return st.id }

// ---- receive ----------------------------------------------------------------

// deliver is called by the session reader with a fresh DATA payload. It enforces
// a hard receive-buffer ceiling as defense-in-depth: a conformant peer never
// sends more than its flow-control window (≤ the largest profile window, 4 MiB),
// so this only trips on a peer that ignores flow control — in which case the
// stream is reset to reclaim memory rather than buffering without bound.
func (st *Stream) deliver(data []byte) {
	st.rmu.Lock()
	st.rbuf = append(st.rbuf, data...)
	over := len(st.rbuf) > maxRecvBuffer
	st.rcond.Signal()
	st.rmu.Unlock()
	st.s.accountRecv(len(data))
	if over {
		st.setErr(ErrStreamReset)
		st.s.resetStream(st.id)
		_ = st.s.queue(outFrame{typ: frameRST, id: st.id}, true)
	}
}

func (st *Stream) remoteFIN() {
	st.rmu.Lock()
	st.rFIN = true
	st.rcond.Broadcast()
	st.rmu.Unlock()
	st.remoteClosed.Store(true)
	st.maybeReap()
}

// Read implements io.Reader.
func (st *Stream) Read(p []byte) (int, error) {
	st.rmu.Lock()
	for len(st.rbuf) == 0 {
		if e := st.readErr(); e != nil {
			st.rmu.Unlock()
			return 0, e
		}
		if st.rFIN {
			st.rmu.Unlock()
			return 0, io.EOF
		}
		st.rcond.Wait()
	}
	n := copy(p, st.rbuf)
	st.rbuf = st.rbuf[n:]
	st.s.accountRecv(-n)
	if len(st.rbuf) == 0 {
		st.rbuf = nil // release backing array
	}
	st.consumed += n
	st.drained += n
	var grant int
	if st.consumed >= st.winGrip {
		grant = st.consumed
		st.consumed = 0
		grant += st.growLocked()
	}
	st.rmu.Unlock()

	if grant > 0 {
		// Replenish the peer's send window. WINDOW_UPDATE goes on the HIGH
		// priority queue so it is never stuck behind this session's bulk DATA —
		// otherwise the sender stalls waiting for credit and throughput (notably
		// the lighter/upload direction) collapses under load.
		_ = st.s.queue(outFrame{typ: frameWinUp, id: st.id, ctl: uint32(grant)}, true)
	}
	return n, nil
}

// growLocked doubles the receive window when the reader is draining it faster
// than the window allows, and returns the extra credit to hand the peer.
//
// Turning over a whole window inside growPeriod means the sender had more to
// send and the window is what stopped it — the definition of window-limited.
// Doubling then costs one more round trip to take effect and halves the number
// of times it must happen, so a long path converges in a few steps.
//
// The growth is bounded twice: per stream, so one transfer cannot claim
// unlimited memory; and across the session, so many streams together stay under
// the ceiling that guards this host's RAM. Hitting either bound leaves the
// window where it is, which is the old fixed behaviour rather than a failure.
//
// Callers hold rmu.
func (st *Stream) growLocked() int {
	now := time.Now()
	if st.drained < st.win {
		if now.Sub(st.lastGrow) > growPeriod {
			// Not window-limited in this period; start a fresh one.
			st.drained, st.lastGrow = 0, now
		}
		return 0
	}
	elapsed := now.Sub(st.lastGrow)
	st.drained, st.lastGrow = 0, now
	if elapsed > growPeriod {
		return 0 // drained a window, but slowly: the path is the limit, not us
	}

	next := st.win * 2
	if max := st.s.maxWindow(); next > max {
		next = max
	}
	if next <= st.win {
		return 0
	}
	extra := next - st.win
	if !st.s.reserveWindow(extra) {
		return 0
	}
	st.win = next
	st.winGrip = next / 2
	return extra
}

func (st *Stream) readErr() error {
	st.emu.Lock()
	defer st.emu.Unlock()
	return st.err
}

// ---- send -------------------------------------------------------------------

func (st *Stream) addSendWindow(n int) {
	st.wmu.Lock()
	st.sendWin += n
	st.wcond.Signal()
	st.wmu.Unlock()
}

// Write implements io.Writer, honouring per-stream flow control.
func (st *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		st.wmu.Lock()
		for st.sendWin <= 0 {
			if e := st.readErr(); e != nil {
				st.wmu.Unlock()
				return total, e
			}
			if st.wFIN {
				st.wmu.Unlock()
				return total, ErrStreamClosed
			}
			st.wcond.Wait()
		}
		if e := st.readErr(); e != nil {
			st.wmu.Unlock()
			return total, e
		}
		n := len(p)
		if n > maxFrame {
			n = maxFrame
		}
		if n > st.sendWin {
			n = st.sendWin
		}
		st.sendWin -= n
		st.wmu.Unlock()

		buf := getBuf()[:n]
		copy(buf, p[:n])
		if err := st.s.queue(outFrame{typ: frameData, id: st.id, data: buf, pooled: true}, st.hi); err != nil {
			return total, err
		}
		p = p[n:]
		total += n
	}
	return total, nil
}

// Close half-closes the stream (sends FIN) and stops further writes.
func (st *Stream) Close() error {
	st.wmu.Lock()
	if st.wFIN {
		st.wmu.Unlock()
		return nil
	}
	st.wFIN = true
	st.wcond.Broadcast()
	st.wmu.Unlock()

	_ = st.s.queue(outFrame{typ: frameFIN, id: st.id}, st.hi)
	st.localClosed.Store(true)
	// Reaps from the session map once the peer has also FIN'd; buffered read
	// data remains readable via the Stream handle after removal.
	st.maybeReap()
	return nil
}

// setErr aborts the stream (session teardown or RST) and wakes blocked callers.
func (st *Stream) setErr(err error) {
	st.emu.Lock()
	if st.err == nil {
		st.err = err
	}
	st.emu.Unlock()
	st.rmu.Lock()
	st.rcond.Broadcast()
	st.rmu.Unlock()
	st.wmu.Lock()
	st.wcond.Broadcast()
	st.wmu.Unlock()
}

// SetReadDeadline is a no-op shim; callers drive lifetime via Close/ctx. It
// exists so a Stream can stand in where a minimal deadline setter is expected.
func (st *Stream) SetReadDeadline(time.Time) error { return nil }

// windowForTest reports the currently advertised receive window.
func (st *Stream) windowForTest() int {
	st.rmu.Lock()
	defer st.rmu.Unlock()
	return st.win
}
