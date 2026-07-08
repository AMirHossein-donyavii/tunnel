// Package forward implements the Emergency Tunnel data path on top of an
// authenticated, encrypted link (crypto.SecureConn) supplied by a transport.
//
// Model (independent of transport):
//
//	Entry side (Iran): owns the forwarded ports. Each pooled link is held by a
//	  worker that waits for a user connection, sends an OPEN control frame
//	  (remote port + optional PROXY-v2 header) and splices.
//	Exit side (Kharej): each pooled link is held by a worker that waits for an
//	  OPEN, dials the local service (127.0.0.1:remote), optionally writes the
//	  PROXY-v2 header, and splices.
//
// Who dials vs. accepts is decided by mode (reverse => Kharej dials). That is
// orthogonal to entry/exit, which is decided by role. Because each worker owns
// exactly one link for its lifetime, the pool size stays exact and there are no
// goroutine or connection leaks.
package forward

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/crypto"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/proxyproto"
	"github.com/emergency-tunnel/et/internal/transport"
)

const (
	frameOpen     = 0x01
	maxPPHeader   = 232 // PROXY v2 max header we emit
	dialLocalTO   = 8 * time.Second
	assignTO      = 4 * time.Second
	handshakeSlot = 128 // max concurrent inbound handshakes (flood guard)
)

// bufPool provides 32 KiB splice buffers, reused to keep allocations (and thus
// GC pressure on small VPS targets) near zero on the hot path.
var bufPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

type target struct {
	remote int
	pp     bool
}

// assignment is a user connection waiting for a worker to carry it.
type assignment struct {
	uc net.Conn
	t  target
	pp []byte
}

// Engine runs one tunnel's data path.
type Engine struct {
	cfg      *config.Config
	log      *logx.Logger
	psk      []byte
	cipher   string
	dialer   transport.Dialer
	listener transport.Listener
	isDialer bool
	isEntry  bool

	routes map[int]target        // listen port -> target (entry side)
	assign chan *assignment      // entry: user conns waiting for a worker
	hsSem  chan struct{}         // inbound handshake concurrency limit
	nowSec func() int64

	stats struct {
		activeConns int64
		totalConns  uint64
		rxBytes     uint64
		txBytes     uint64
		linkErrors  uint64
	}
}

// New builds an Engine from validated config.
func New(cfg *config.Config, log *logx.Logger) (*Engine, error) {
	tr, err := transport.Get(cfg.Transport)
	if err != nil {
		return nil, err
	}
	key, err := cfg.KeyBytes()
	if err != nil {
		return nil, err
	}
	e := &Engine{
		cfg:      cfg,
		log:      log,
		psk:      key,
		cipher:   cfg.Cipher,
		isDialer: cfg.IsDialer(),
		isEntry:  cfg.IsEntry(),
		routes:   map[int]target{},
		assign:   make(chan *assignment),
		hsSem:    make(chan struct{}, handshakeSlot),
		nowSec:   func() int64 { return time.Now().Unix() },
	}
	if e.isEntry {
		for _, spec := range cfg.Forwards {
			f, err := config.ParseForward(spec, cfg.ProxyProtocol)
			if err != nil {
				return nil, err
			}
			for p := f.ListenStart; p <= f.ListenEnd; p++ {
				e.routes[p] = target{remote: f.RemoteFor(p), pp: f.ProxyProto}
			}
		}
	}
	if e.isDialer {
		if e.dialer, err = tr.NewDialer(cfg, log); err != nil {
			return nil, err
		}
	} else {
		if e.listener, err = tr.NewListener(cfg, log); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// Run starts the data path and blocks until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	// Link supply: dialer keeps `pool` warm workers; listener spawns one per
	// inbound link.
	if e.isDialer {
		for i := 0; i < e.cfg.Pool; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); e.dialLoop(ctx) }()
		}
	} else {
		wg.Add(1)
		go func() { defer wg.Done(); e.acceptLoop(ctx) }()
	}

	// Entry side serves user connections on the forwarded ports.
	if e.isEntry {
		for port := range e.routes {
			p := port
			wg.Add(1)
			go func() { defer wg.Done(); e.serveForward(ctx, p) }()
		}
	}

	wg.Add(1)
	go func() { defer wg.Done(); e.statsLoop(ctx) }()

	e.log.Info("engine started role=%s mode=%s transport=%s pool=%d cipher=%s entry=%v dialer=%v",
		e.cfg.Role, e.cfg.Mode, e.cfg.Transport, e.cfg.Pool, e.cfg.Cipher, e.isEntry, e.isDialer)

	<-ctx.Done()
	if e.dialer != nil {
		_ = e.dialer.Close()
	}
	if e.listener != nil {
		_ = e.listener.Close()
	}
	wg.Wait()
	return nil
}

// ---- Link supply -----------------------------------------------------------

// dialLoop keeps exactly one live worker, redialing after its link is consumed
// or fails. `pool` copies of this run concurrently on the dialing side.
func (e *Engine) dialLoop(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		raw, err := e.dialer.Dial(ctx)
		if err != nil {
			e.linkErr("dial: %v", err)
			if !backoffSleep(ctx, &backoff) {
				return
			}
			continue
		}
		link, err := crypto.ClientHandshake(raw, e.cipher, e.psk, e.nowSec())
		if err != nil {
			_ = raw.Close()
			e.linkErr("client handshake: %v", err)
			if !backoffSleep(ctx, &backoff) {
				return
			}
			continue
		}
		backoff = time.Second
		e.runWorker(ctx, link) // blocks until the link is done
	}
}

// acceptLoop handshakes inbound links and runs a worker per link.
func (e *Engine) acceptLoop(ctx context.Context) {
	for ctx.Err() == nil {
		raw, err := e.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			e.linkErr("accept: %v", err)
			b := 500 * time.Millisecond
			if !backoffSleep(ctx, &b) {
				return
			}
			continue
		}
		select {
		case e.hsSem <- struct{}{}:
		default:
			// Too many concurrent handshakes: shed load rather than exhaust RAM.
			_ = raw.Close()
			continue
		}
		go func() {
			defer func() { <-e.hsSem }()
			link, err := crypto.ServerHandshake(raw, e.cipher, e.psk, e.nowSec())
			if err != nil {
				_ = raw.Close()
				e.linkErr("server handshake from %s: %v", raw.RemoteAddr(), err)
				return
			}
			e.runWorker(ctx, link)
		}()
	}
}

// runWorker drives one authenticated link for its entire life, then returns so
// the caller can refill the pool.
func (e *Engine) runWorker(ctx context.Context, link *crypto.SecureConn) {
	if e.isEntry {
		e.entryWork(ctx, link)
	} else {
		e.exitWork(ctx, link)
	}
}

// ---- Entry side ------------------------------------------------------------

// entryWork waits for one user assignment, carries it, then returns.
func (e *Engine) entryWork(ctx context.Context, link *crypto.SecureConn) {
	select {
	case a := <-e.assign:
		if err := writeOpen(link, a.t.remote, a.pp); err != nil {
			// Stale link: drop this user (they will reconnect) and refill.
			_ = a.uc.Close()
			_ = link.Close()
			e.linkErr("open on stale link: %v", err)
			return
		}
		atomic.AddInt64(&e.stats.activeConns, 1)
		atomic.AddUint64(&e.stats.totalConns, 1)
		e.splice(link, a.uc)
		atomic.AddInt64(&e.stats.activeConns, -1)
	case <-ctx.Done():
		_ = link.Close()
	}
}

func (e *Engine) serveForward(ctx context.Context, port int) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		e.log.Error("cannot listen on forwarded port %d: %v", port, err)
		return
	}
	t := e.routes[port]
	e.log.Info("forwarding tcp/%d -> remote tcp/%d (proxy_protocol=%v)", port, t.remote, t.pp)
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		uc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		var pp []byte
		if t.pp {
			pp = proxyproto.Header(uc.RemoteAddr(), uc.LocalAddr())
		}
		a := &assignment{uc: uc, t: t, pp: pp}
		select {
		case e.assign <- a: // a worker takes ownership of uc
		case <-time.After(assignTO):
			_ = uc.Close()
			e.linkErr("no tunnel link available for %s within %s", uc.RemoteAddr(), assignTO)
		case <-ctx.Done():
			_ = uc.Close()
			return
		}
	}
}

// ---- Exit side -------------------------------------------------------------

// exitWork waits for an OPEN, bridges to the local service, then returns.
func (e *Engine) exitWork(ctx context.Context, link *crypto.SecureConn) {
	remote, pp, err := readOpen(ctx, link)
	if err != nil {
		if !errors.Is(err, io.EOF) && ctx.Err() == nil {
			e.linkErr("read open: %v", err)
		}
		_ = link.Close()
		return
	}
	local, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", remote), dialLocalTO)
	if err != nil {
		e.linkErr("dial local service 127.0.0.1:%d: %v", remote, err)
		_ = link.Close()
		return
	}
	if tc, ok := local.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if len(pp) > 0 {
		if _, err := local.Write(pp); err != nil {
			_ = local.Close()
			_ = link.Close()
			return
		}
	}
	atomic.AddInt64(&e.stats.activeConns, 1)
	atomic.AddUint64(&e.stats.totalConns, 1)
	e.splice(link, local)
	atomic.AddInt64(&e.stats.activeConns, -1)
}

// ---- Control frame ---------------------------------------------------------

// writeOpen sends the OPEN control frame as a single AEAD frame.
func writeOpen(link *crypto.SecureConn, remote int, pp []byte) error {
	if len(pp) > maxPPHeader {
		pp = pp[:maxPPHeader]
	}
	buf := make([]byte, 5+len(pp))
	buf[0] = frameOpen
	binary.BigEndian.PutUint16(buf[1:], uint16(remote))
	binary.BigEndian.PutUint16(buf[3:], uint16(len(pp)))
	copy(buf[5:], pp)
	_ = link.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := link.Write(buf)
	_ = link.SetWriteDeadline(time.Time{})
	return err
}

// readOpen parses the OPEN control frame, aborting if ctx ends.
func readOpen(ctx context.Context, link *crypto.SecureConn) (remote int, pp []byte, err error) {
	stop := context.AfterFunc(ctx, func() { _ = link.SetReadDeadline(time.Now()) })
	defer stop()

	hdr := make([]byte, 5)
	if _, err = io.ReadFull(link, hdr); err != nil {
		return 0, nil, err
	}
	if hdr[0] != frameOpen {
		return 0, nil, fmt.Errorf("unexpected control frame 0x%02x", hdr[0])
	}
	remote = int(binary.BigEndian.Uint16(hdr[1:]))
	ppLen := int(binary.BigEndian.Uint16(hdr[3:]))
	if ppLen > maxPPHeader {
		return 0, nil, fmt.Errorf("proxy header too large: %d", ppLen)
	}
	if ppLen > 0 {
		pp = make([]byte, ppLen)
		if _, err = io.ReadFull(link, pp); err != nil {
			return 0, nil, err
		}
	}
	return remote, pp, nil
}

// ---- Plumbing --------------------------------------------------------------

// splice copies bytes bidirectionally between the tunnel link and a local conn,
// tearing both down when either direction ends.
func (e *Engine) splice(link *crypto.SecureConn, local net.Conn) {
	var once sync.Once
	stop := func() { _ = link.Close(); _ = local.Close() }
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n := e.copy(local, link)
		atomic.AddUint64(&e.stats.rxBytes, n)
		once.Do(stop)
	}()
	go func() {
		defer wg.Done()
		n := e.copy(link, local)
		atomic.AddUint64(&e.stats.txBytes, n)
		once.Do(stop)
	}()
	wg.Wait()
}

func (e *Engine) copy(dst io.Writer, src io.Reader) uint64 {
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	n, _ := io.CopyBuffer(dst, src, *bp)
	return uint64(n)
}

// Stats is a point-in-time snapshot of engine counters.
type Stats struct {
	Active     int64  `json:"active"`
	Total      uint64 `json:"total"`
	RxBytes    uint64 `json:"rx_bytes"`
	TxBytes    uint64 `json:"tx_bytes"`
	LinkErrors uint64 `json:"link_errors"`
}

// Snapshot returns the current counters safely.
func (e *Engine) Snapshot() Stats {
	return Stats{
		Active:     atomic.LoadInt64(&e.stats.activeConns),
		Total:      atomic.LoadUint64(&e.stats.totalConns),
		RxBytes:    atomic.LoadUint64(&e.stats.rxBytes),
		TxBytes:    atomic.LoadUint64(&e.stats.txBytes),
		LinkErrors: atomic.LoadUint64(&e.stats.linkErrors),
	}
}

func (e *Engine) linkErr(f string, a ...any) {
	atomic.AddUint64(&e.stats.linkErrors, 1)
	e.log.Warn(f, a...)
}

func (e *Engine) statsLoop(ctx context.Context) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.log.Info("stats active=%d total=%d rx=%s tx=%s link_errors=%d",
				atomic.LoadInt64(&e.stats.activeConns),
				atomic.LoadUint64(&e.stats.totalConns),
				humanBytes(atomic.LoadUint64(&e.stats.rxBytes)),
				humanBytes(atomic.LoadUint64(&e.stats.txBytes)),
				atomic.LoadUint64(&e.stats.linkErrors))
		}
	}
}

// backoffSleep sleeps for *b (capped) and doubles it, returning false if ctx ends.
func backoffSleep(ctx context.Context, b *time.Duration) bool {
	t := time.NewTimer(*b)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		if *b < 15*time.Second {
			*b *= 2
		}
		return true
	}
}

func humanBytes(n uint64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(u), 0
	for x := n / u; x >= u; x /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}
