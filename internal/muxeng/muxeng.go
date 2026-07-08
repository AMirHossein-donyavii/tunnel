// Package muxeng is the multiplexed L4 reverse-tunnel engine. Instead of one
// TCP link per user connection (the l4 engine), it carries many logical streams
// over a small pool of long-lived, authenticated, tuned links using
// internal/mux. A new user connection costs one SYN frame — no extra TCP or
// crypto handshake — which is the decisive latency win on long-distance links.
package muxeng

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/crypto"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/mux"
	"github.com/emergency-tunnel/et/internal/nettune"
	"github.com/emergency-tunnel/et/internal/proxyproto"
	"github.com/emergency-tunnel/et/internal/transport"
)

const (
	dialLocalTO = 8 * time.Second
	openRetry   = 3
	openWaitTO  = 4 * time.Second
)

var bufPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

type target struct {
	remote int
	pp     bool
}

// Engine runs one multiplexed tunnel.
type Engine struct {
	cfg      *config.Config
	log      *logx.Logger
	cipher   string
	isDialer bool
	isEntry  bool
	dialer   transport.Dialer
	listener transport.Listener
	tune     nettune.Options
	muxCfg   mux.Config

	routes map[int]target

	set sessionSet

	stats struct {
		activeStreams int64
		totalStreams  uint64
		rxBytes       uint64
		txBytes       uint64
		sessionErrs   uint64
	}
}

// New builds a mux engine from validated config.
func New(cfg *config.Config, log *logx.Logger) (*Engine, error) {
	tr, err := transport.Get(cfg.Transport)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		cfg:      cfg,
		log:      log,
		cipher:   cfg.Cipher,
		isDialer: cfg.IsDialer(),
		isEntry:  cfg.IsEntry(),
		tune:     nettune.LinkOptions(cfg.Profile, cfg.SoSndbuf, cfg.SoRcvbuf),
		routes:   map[int]target{},
	}
	e.muxCfg = mux.Config{
		KeepAlive:        time.Duration(orDefault(cfg.HeartbeatInterval, 10)) * time.Second,
		KeepAliveTimeout: time.Duration(orDefault(cfg.HeartbeatTimeout, 25)) * time.Second,
		AcceptBacklog:    512,
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

// Run establishes the session pool and serves traffic until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	if e.isDialer {
		for i := 0; i < e.cfg.Pool; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); e.dialSession(ctx) }()
		}
	} else {
		wg.Add(1)
		go func() { defer wg.Done(); e.acceptSessions(ctx) }()
	}

	if e.isEntry {
		for port := range e.routes {
			p := port
			wg.Add(1)
			go func() { defer wg.Done(); e.serveForward(ctx, p) }()
		}
	}

	e.log.Info("mux engine started role=%s mode=%s transport=%s sessions=%d cipher=%s entry=%v dialer=%v",
		e.cfg.Role, e.cfg.Mode, e.cfg.Transport, e.cfg.Pool, e.cfg.Cipher, e.isEntry, e.isDialer)

	<-ctx.Done()
	if e.dialer != nil {
		_ = e.dialer.Close()
	}
	if e.listener != nil {
		_ = e.listener.Close()
	}
	e.set.closeAll()
	wg.Wait()
	return nil
}

// ---- session supply ---------------------------------------------------------

func (e *Engine) dialSession(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		raw, err := e.dialer.Dial(ctx)
		if err != nil {
			e.sessionErr("dial: %v", err)
			if !sleepCtx(ctx, &backoff) {
				return
			}
			continue
		}
		nettune.Apply(raw, e.tune)
		link, err := crypto.ClientHandshake(raw, e.cipher)
		if err != nil {
			_ = raw.Close()
			e.sessionErr("handshake: %v", err)
			if !sleepCtx(ctx, &backoff) {
				return
			}
			continue
		}
		backoff = time.Second
		sess := mux.Client(link, e.muxCfg)
		e.serveSession(ctx, sess)
	}
}

func (e *Engine) acceptSessions(ctx context.Context) {
	for ctx.Err() == nil {
		raw, err := e.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			e.sessionErr("accept: %v", err)
			continue
		}
		nettune.Apply(raw, e.tune)
		go func() {
			link, err := crypto.ServerHandshake(raw, e.cipher)
			if err != nil {
				_ = raw.Close()
				e.sessionErr("handshake from %s: %v", raw.RemoteAddr(), err)
				return
			}
			e.serveSession(ctx, mux.Server(link, e.muxCfg))
		}()
	}
}

// serveSession registers a session and either serves inbound streams (exit) or
// holds it available for the user handlers (entry) until it dies.
func (e *Engine) serveSession(ctx context.Context, sess *mux.Session) {
	e.set.add(sess)
	defer func() { e.set.remove(sess); sess.Close() }()

	if e.isEntry {
		// Entry opens streams on demand; the session's own keepalive detects
		// death. Just hold it registered until it dies or ctx ends.
		select {
		case <-ctx.Done():
		case <-sess.Done():
		}
		return
	}
	// Exit: accept and serve streams.
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go e.serveExitStream(st)
	}
}

// ---- exit side --------------------------------------------------------------

func (e *Engine) serveExitStream(st *mux.Stream) {
	dest := st.Dest()
	if len(dest) < 2 {
		_ = st.Close()
		return
	}
	remote := int(binary.BigEndian.Uint16(dest[:2]))
	pp := dest[2:]

	local, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", remote), dialLocalTO)
	if err != nil {
		e.sessionErr("dial local 127.0.0.1:%d: %v", remote, err)
		_ = st.Close()
		return
	}
	if tc, ok := local.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if len(pp) > 0 {
		if _, err := local.Write(pp); err != nil {
			_ = local.Close()
			_ = st.Close()
			return
		}
	}
	atomic.AddInt64(&e.stats.activeStreams, 1)
	atomic.AddUint64(&e.stats.totalStreams, 1)
	e.splice(st, local)
	atomic.AddInt64(&e.stats.activeStreams, -1)
}

// ---- entry side -------------------------------------------------------------

func (e *Engine) serveForward(ctx context.Context, port int) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		e.log.Error("cannot listen on forwarded port %d: %v", port, err)
		return
	}
	t := e.routes[port]
	e.log.Info("mux forwarding tcp/%d -> remote tcp/%d (proxy_protocol=%v)", port, t.remote, t.pp)
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

func (e *Engine) handleUser(ctx context.Context, uc net.Conn, t target) {
	dest := make([]byte, 2, 2+232)
	binary.BigEndian.PutUint16(dest, uint16(t.remote))
	if t.pp {
		dest = append(dest, proxyproto.Header(uc.RemoteAddr(), uc.LocalAddr())...)
	}

	deadline := time.Now().Add(openWaitTO)
	for attempt := 0; attempt < openRetry && ctx.Err() == nil; attempt++ {
		sess := e.set.pick()
		if sess == nil {
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(50 * time.Millisecond)
			attempt--
			continue
		}
		st, err := sess.OpenStream(dest, false)
		if err != nil {
			continue // session died; try another
		}
		atomic.AddInt64(&e.stats.activeStreams, 1)
		atomic.AddUint64(&e.stats.totalStreams, 1)
		e.splice(st, uc)
		atomic.AddInt64(&e.stats.activeStreams, -1)
		return
	}
	e.sessionErr("no session available for %s", uc.RemoteAddr())
	_ = uc.Close()
}

// ---- plumbing ---------------------------------------------------------------

// splice bridges a mux stream and a local conn bidirectionally.
func (e *Engine) splice(st *mux.Stream, local net.Conn) {
	var once sync.Once
	stop := func() { _ = st.Close(); _ = local.Close() }
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n := e.copy(local, st)
		atomic.AddUint64(&e.stats.rxBytes, n)
		once.Do(stop)
	}()
	go func() {
		defer wg.Done()
		n := e.copy(st, local)
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

func (e *Engine) sessionErr(f string, a ...any) {
	atomic.AddUint64(&e.stats.sessionErrs, 1)
	e.log.Warn(f, a...)
}

// Stats is a point-in-time snapshot.
type Stats struct {
	Sessions      int    `json:"sessions"`
	ActiveStreams int64  `json:"active_streams"`
	TotalStreams  uint64 `json:"total_streams"`
	RxBytes       uint64 `json:"rx_bytes"`
	TxBytes       uint64 `json:"tx_bytes"`
	SessionErrors uint64 `json:"session_errors"`
	RTTms         int64  `json:"rtt_ms"`
}

// Snapshot returns current counters (as any, for the shared engine interface).
func (e *Engine) Snapshot() any {
	return Stats{
		Sessions:      e.set.count(),
		ActiveStreams: atomic.LoadInt64(&e.stats.activeStreams),
		TotalStreams:  atomic.LoadUint64(&e.stats.totalStreams),
		RxBytes:       atomic.LoadUint64(&e.stats.rxBytes),
		TxBytes:       atomic.LoadUint64(&e.stats.txBytes),
		SessionErrors: atomic.LoadUint64(&e.stats.sessionErrs),
		RTTms:         e.set.bestRTT().Milliseconds(),
	}
}

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func sleepCtx(ctx context.Context, b *time.Duration) bool {
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
