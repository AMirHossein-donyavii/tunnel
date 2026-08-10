// Package directeng is the non-multiplexed reverse tunnel engine: one tunnel
// connection per user connection.
//
// The mux engine is faster — a new user connection costs one frame there
// instead of a TCP and crypto handshake here, which is worth 1-2 RTT per
// connection on a long path. This engine exists for the case where that is not
// the deciding factor:
//
//   - a few long-lived, high-volume connections (a VPN carrying its own
//     multiplexing already, a single big transfer) gain nothing from a second
//     layer of multiplexing and lose a little to its framing;
//   - a small number of independent TCP flows is a more ordinary traffic shape
//     than one long-lived connection carrying everything, which matters where
//     flow-level fingerprinting is the concern;
//   - head-of-line blocking is impossible between connections, because they do
//     not share a carrier at all.
//
// Everything below it is shared: the same transports (tcp, ws, udp), the same
// ephemeral-X25519 handshake and AEAD framing, the same socket tuning.
package directeng

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/crypto"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/nettune"
	"github.com/emergency-tunnel/et/internal/proxyproto"
	"github.com/emergency-tunnel/et/internal/transport"
)

const (
	dialLocalTO = 8 * time.Second
	dialPeerTO  = 10 * time.Second
	// maxDest bounds the destination header: a port plus at most a PROXY v2
	// header. Anything larger is a malformed or hostile peer.
	maxDest = 256
)

var bufPool = sync.Pool{New: func() any { b := make([]byte, 64*1024); return &b }}

type target struct {
	remote int
	pp     bool
}

// Engine runs one non-multiplexed tunnel.
type Engine struct {
	cfg      *config.Config
	log      *logx.Logger
	cipher   string
	isDialer bool
	isEntry  bool
	exitHost string
	tr       transport.Transport
	dialer   transport.Dialer
	listener transport.Listener
	tune     nettune.Options
	routes   map[int]target
	parked   chan *parkedConn

	stats struct {
		active     int64
		total      uint64
		rxBytes    uint64
		txBytes    uint64
		errs       uint64
		forwardsUp int64
	}
	up atomic.Bool
}

// New builds a direct engine from validated config.
func New(cfg *config.Config, log *logx.Logger) (*Engine, error) {
	tr, err := transport.Get(cfg.Transport)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		cfg: cfg, log: log, cipher: cfg.Cipher,
		isDialer: cfg.IsDialer(), isEntry: cfg.IsEntry(),
		exitHost: cfg.ExitHost, tr: tr,
		tune:   nettune.LinkOptions(cfg.Profile, cfg.SoSndbuf, cfg.SoRcvbuf),
		routes: map[int]target{},
	}
	if e.exitHost == "" {
		e.exitHost = "127.0.0.1"
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
	return e, nil
}

// Run serves until ctx is cancelled.
//
// The direction is fixed by the reverse design: the exit (Kharej) always dials
// the entry (Iran). A user connection therefore cannot open a fresh tunnel
// connection on demand — instead the exit keeps a small pool of pre-opened,
// already-authenticated connections parked at the entry, and each user
// connection consumes one. That preserves "one connection per user connection"
// on the wire while still costing zero handshakes at connect time.
func (e *Engine) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	if e.isDialer {
		d, err := e.tr.NewDialer(e.cfg, e.log)
		if err != nil {
			return err
		}
		e.dialer = d
		pool := e.cfg.Pool
		if pool < 1 {
			pool = 4
		}
		for i := 0; i < pool; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); e.exitWorker(ctx) }()
		}
	} else {
		l, err := e.tr.NewListener(e.cfg, e.log)
		if err != nil {
			return err
		}
		e.listener = l
		e.parked = make(chan *parkedConn, 256)
		wg.Add(1)
		go func() { defer wg.Done(); e.acceptLinks(ctx) }()
		for port := range e.routes {
			p := port
			wg.Add(1)
			go func() { defer wg.Done(); e.serveForward(ctx, p) }()
		}
	}

	e.log.Info("direct engine started role=%s transport=%s pool=%d cipher=%s entry=%v dialer=%v",
		e.cfg.Role, e.cfg.Transport, e.cfg.Pool, e.cfg.Cipher, e.isEntry, e.isDialer)

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

// parkedConn is an authenticated tunnel connection waiting at the entry for a
// user connection to claim it.
type parkedConn struct {
	sc   *crypto.SecureConn
	dead chan struct{}
}

// ---- exit side (dialer) -----------------------------------------------------

// exitWorker keeps exactly one connection parked at the entry. When the entry
// uses it, the worker opens the next one — so the pool size is exact and there
// are no leaked dials.
func (e *Engine) exitWorker(ctx context.Context) {
	backoff := 250 * time.Millisecond
	for ctx.Err() == nil {
		raw, err := e.dialer.Dial(ctx)
		if err != nil {
			e.fail("dial: %v", err)
			if !sleepCtx(ctx, &backoff) {
				return
			}
			continue
		}
		nettune.Apply(raw, e.tune)
		sc, err := crypto.ClientHandshake(raw, e.cipher)
		if err != nil {
			_ = raw.Close()
			e.fail("handshake: %v", err)
			if !sleepCtx(ctx, &backoff) {
				return
			}
			continue
		}
		backoff = 250 * time.Millisecond
		e.up.Store(true)
		// Block until the entry sends a destination for this connection.
		e.serveOne(ctx, sc)
	}
}

// serveOne waits for the entry's destination header, dials the local service
// and splices. The read has no deadline: the connection is deliberately parked
// until a user arrives.
func (e *Engine) serveOne(ctx context.Context, sc *crypto.SecureConn) {
	defer sc.Close()
	stop := context.AfterFunc(ctx, func() { _ = sc.Close() })
	defer stop()

	dest, err := readDest(sc)
	if err != nil {
		return
	}
	if len(dest) < 2 {
		return
	}
	remote := int(binary.BigEndian.Uint16(dest[:2]))
	pp := dest[2:]

	addr := net.JoinHostPort(e.exitHost, strconv.Itoa(remote))
	local, err := net.DialTimeout("tcp", addr, dialLocalTO)
	if err != nil {
		e.fail("dial exit service %s: %v", addr, err)
		return
	}
	defer local.Close()
	if tc, ok := local.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if len(pp) > 0 {
		if _, err := local.Write(pp); err != nil {
			return
		}
	}
	atomic.AddInt64(&e.stats.active, 1)
	atomic.AddUint64(&e.stats.total, 1)
	e.splice(sc, local)
	atomic.AddInt64(&e.stats.active, -1)
}

// ---- entry side (listener) --------------------------------------------------

func (e *Engine) acceptLinks(ctx context.Context) {
	for ctx.Err() == nil {
		raw, err := e.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			e.fail("accept: %v", err)
			continue
		}
		nettune.Apply(raw, e.tune)
		go func() {
			sc, err := crypto.ServerHandshake(raw, e.cipher)
			if err != nil {
				_ = raw.Close()
				e.fail("handshake from %s: %v", raw.RemoteAddr(), err)
				return
			}
			pc := &parkedConn{sc: sc, dead: make(chan struct{})}
			e.up.Store(true)
			select {
			case e.parked <- pc:
			case <-ctx.Done():
				_ = sc.Close()
			default:
				// More parked connections than users: the peer's pool is larger
				// than this side needs. Drop the excess rather than hoarding it.
				_ = sc.Close()
			}
		}()
	}
}

func (e *Engine) serveForward(ctx context.Context, port int) {
	lc := net.ListenConfig{}
	var ln net.Listener
	backoff := time.Second
	warned := false
	for {
		var err error
		ln, err = lc.Listen(ctx, "tcp", fmt.Sprintf(":%d", port))
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return
		}
		if !warned {
			e.log.Error("cannot bind port %d yet (%v) — retrying", port, err)
			warned = true
		}
		if !sleepCtx(ctx, &backoff) {
			return
		}
	}
	defer ln.Close()
	t := e.routes[port]
	atomic.AddInt64(&e.stats.forwardsUp, 1)
	defer atomic.AddInt64(&e.stats.forwardsUp, -1)
	e.log.Info("direct forwarding tcp/%d -> exit tcp/%d (proxy_protocol=%v)", port, t.remote, t.pp)
	go func() { <-ctx.Done(); _ = ln.Close() }()

	for {
		uc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if tc, ok := uc.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		go e.handleUser(ctx, uc, t)
	}
}

// handleUser claims a parked tunnel connection for this user connection.
func (e *Engine) handleUser(ctx context.Context, uc net.Conn, t target) {
	dest := make([]byte, 2, 2+maxDest)
	binary.BigEndian.PutUint16(dest, uint16(t.remote))
	if t.pp {
		dest = append(dest, proxyproto.Header(uc.RemoteAddr(), uc.LocalAddr())...)
	}

	var pc *parkedConn
	select {
	case pc = <-e.parked:
	case <-time.After(4 * time.Second):
		e.fail("no tunnel connection available for %s", uc.RemoteAddr())
		_ = uc.Close()
		return
	case <-ctx.Done():
		_ = uc.Close()
		return
	}
	defer pc.sc.Close()

	if err := writeDest(pc.sc, dest); err != nil {
		e.fail("sending destination: %v", err)
		_ = uc.Close()
		return
	}
	atomic.AddInt64(&e.stats.active, 1)
	atomic.AddUint64(&e.stats.total, 1)
	e.splice(pc.sc, uc)
	atomic.AddInt64(&e.stats.active, -1)
	_ = uc.Close()
}

// ---- shared -----------------------------------------------------------------

// writeDest sends the length-prefixed destination header.
func writeDest(sc *crypto.SecureConn, dest []byte) error {
	if len(dest) > maxDest {
		return fmt.Errorf("direct: destination header too large")
	}
	buf := make([]byte, 2+len(dest))
	binary.BigEndian.PutUint16(buf, uint16(len(dest)))
	copy(buf[2:], dest)
	_, err := sc.Write(buf)
	return err
}

func readDest(sc *crypto.SecureConn) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(sc, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n < 2 || n > maxDest {
		return nil, fmt.Errorf("direct: bad destination length %d", n)
	}
	dest := make([]byte, n)
	if _, err := io.ReadFull(sc, dest); err != nil {
		return nil, err
	}
	return dest, nil
}

func (e *Engine) splice(tunnelSide io.ReadWriteCloser, local net.Conn) {
	var once sync.Once
	stop := func() { _ = tunnelSide.Close(); _ = local.Close() }
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		atomic.AddUint64(&e.stats.rxBytes, e.copy(local, tunnelSide))
		once.Do(stop)
	}()
	go func() {
		defer wg.Done()
		atomic.AddUint64(&e.stats.txBytes, e.copy(tunnelSide, local))
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

func (e *Engine) fail(f string, a ...any) {
	atomic.AddUint64(&e.stats.errs, 1)
	e.log.Warn(f, a...)
}

func sleepCtx(ctx context.Context, b *time.Duration) bool {
	t := time.NewTimer(*b)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		if *b < 5*time.Second {
			*b *= 2
		}
		return true
	}
}

// Stats is a point-in-time snapshot.
type Stats struct {
	ActiveConns        int64  `json:"active_conns"`
	TotalConns         uint64 `json:"total_conns"`
	RxBytes            uint64 `json:"rx_bytes"`
	TxBytes            uint64 `json:"tx_bytes"`
	Errors             uint64 `json:"errors"`
	ParkedConns        int    `json:"parked_conns"`
	ForwardsConfigured int    `json:"forwards_configured"`
	ForwardsUp         int64  `json:"forwards_up"`
}

func (e *Engine) Healthy() bool { return e.up.Load() }

func (e *Engine) Snapshot() any {
	parked := 0
	if e.parked != nil {
		parked = len(e.parked)
	}
	return Stats{
		ActiveConns:        atomic.LoadInt64(&e.stats.active),
		TotalConns:         atomic.LoadUint64(&e.stats.total),
		RxBytes:            atomic.LoadUint64(&e.stats.rxBytes),
		TxBytes:            atomic.LoadUint64(&e.stats.txBytes),
		Errors:             atomic.LoadUint64(&e.stats.errs),
		ParkedConns:        parked,
		ForwardsConfigured: len(e.routes),
		ForwardsUp:         atomic.LoadInt64(&e.stats.forwardsUp),
	}
}
