// Package ovpneng is a data plane built for one job: carrying an OpenVPN/TCP
// session across a hostile path without the two TCP layers destroying each
// other.
//
// # Why this is not just another forward
//
// OpenVPN in TCP mode is a reliable stream, and so is the carrier that hides it.
// Stacking them is the classic pathology: both layers retransmit, and — far more
// damaging — the relay in the middle buffers. Every byte held in the middle is
// delay the INNER connection measures as round-trip time, so its congestion
// control believes the path is fatter and slower than it is, overshoots, and
// then stalls for whole seconds. It looks fine on a quiet link and falls apart
// the moment a real page loads, which is when people conclude they were
// detected.
//
// The cure is not obfuscation. It is refusing to buffer:
//
//   - Small relay buffers. This engine moves bytes in 16 KiB units and never
//     reads ahead beyond one of them, so the inner connection's view of the path
//     stays honest and its timers stay sane. A larger buffer measures better on
//     a benchmark and behaves worse in use — the reason the general-purpose
//     engine's 64 KiB is wrong here.
//   - The kernel's send queue is capped too (TCP_NOTSENT_LOWAT, via nettune), so
//     the backlog cannot simply move from our buffer into the socket.
//   - Backpressure instead of shedding. A reliable stream cannot drop a byte
//     without corrupting it, so when the carrier slows, this engine stops
//     reading from the VPN. The inner sender's window closes, which is exactly
//     what TCP flow control is for, and the sender slows down instead of
//     queueing.
//
// # One carrier connection per VPN connection, established in advance
//
// No multiplexer. A multiplexed link shares one window and one write queue
// between everything on it, so a bulk download adds delay to the VPN's control
// channel and a stalled stream can hold up its neighbours. Here each OpenVPN
// connection gets its own carrier connection, tuned for it and shared with
// nothing — the VPN's traffic can only ever be delayed by itself.
//
// Those connections are opened before they are needed. The Foreign server keeps
// a few authenticated carriers parked at the Iran server, so when a VPN client
// arrives the carrier is already up: no dial, no TLS, no key exchange in front
// of the user. On the long path this tunnel exists for, that removes two or
// three round trips from every connect — and OpenVPN reconnects often enough
// that this is felt, not theoretical.
//
// # What hides it
//
// Whatever transport is configured: stealth (no fingerprint at all), wss (an
// HTTPS website), ws, or plain tcp. The OpenVPN handshake never appears on the
// wire — it is inside this tunnel's own AEAD — so what an observer can match on
// is the carrier's shape, not OpenVPN's.
package ovpneng

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/crypto"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/nettune"
	"github.com/emergency-tunnel/et/internal/transport"
)

const (
	// relayBuf is the unit this engine moves bytes in.
	//
	// It is deliberately small. In a TCP-over-TCP relay the buffer is not a
	// throughput knob, it is added latency: bytes sitting here are bytes the
	// inner connection has sent and not seen acknowledged, so they inflate its
	// RTT estimate and its congestion window with it. 16 KiB is comfortably more
	// than one full-size segment — so it never limits throughput — while being
	// small enough that the inner connection's timers still describe the real
	// path.
	relayBuf = 16 << 10

	// claimWait bounds how long a VPN client waits for a carrier before being
	// told no. Short on purpose: OpenVPN retries a refused connection faster and
	// more cleanly than anything gained by making it wait, and a warm pool means
	// this is only ever reached when the tunnel itself is down.
	claimWait = 2 * time.Second

	// exitDialTO bounds dialing the local OpenVPN server, which is on this
	// machine and either answers at once or is not running.
	exitDialTO = 4 * time.Second
)

var bufPool = sync.Pool{New: func() any { b := make([]byte, relayBuf); return &b }}

// Engine carries OpenVPN/TCP between the two servers.
type Engine struct {
	cfg      *config.Config
	log      *logx.Logger
	cipher   string
	isEntry  bool
	isDialer bool
	port     int    // the OpenVPN port
	exitHost string // where the exit finds the OpenVPN server

	dialer   transport.Dialer
	listener transport.Listener
	tune     nettune.Options

	// parked holds authenticated carrier connections waiting for a VPN client.
	// Only the entry (the carrier's listener) has one.
	parked chan *crypto.SecureConn

	up atomic.Bool

	stats struct {
		accepted  uint64 // VPN connections taken from clients
		connected uint64 // of those, carried end to end
		refused   uint64 // no carrier was ready
		active    int64
		toExit    uint64 // bytes travelling client -> OpenVPN server
		toClient  uint64 // bytes travelling OpenVPN server -> client
		waitMs    int64  // how long the last client waited for a carrier
		ready     int64  // carriers parked and ready right now
	}
}

// New builds the engine from validated config.
func New(cfg *config.Config, log *logx.Logger) (*Engine, error) {
	tr, err := transport.Get(cfg.Transport)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		cfg:      cfg,
		log:      log,
		cipher:   cfg.Cipher,
		isEntry:  cfg.IsEntry(),
		isDialer: cfg.IsDialer(),
		port:     cfg.OpenVPNPort,
		exitHost: orDefault(cfg.ExitHost, "127.0.0.1"),
		tune:     nettune.LinkOptions(cfg.Profile, cfg.SoSndbuf, cfg.SoRcvbuf),
	}
	if e.isDialer {
		if e.dialer, err = tr.NewDialer(cfg, log); err != nil {
			return nil, err
		}
	} else {
		if e.listener, err = tr.NewListener(cfg, log); err != nil {
			return nil, err
		}
		e.parked = make(chan *crypto.SecureConn, warmPool(cfg.Pool)*2)
	}
	return e, nil
}

// warmPool is how many carriers are kept ready. Each one costs an idle TCP
// connection and nothing else, and each one is a VPN connect that does not have
// to wait for a handshake — so this errs generous.
func warmPool(p int) int {
	if p < 2 {
		return 4
	}
	if p > 32 {
		return 32
	}
	return p
}

// Run serves until ctx is cancelled.
//
// Reverse mode only, like the rest of this project: the Foreign server dials
// the Iran server. That makes the Iran side the carrier's listener and the
// Foreign side its dialer, independently of which side the VPN clients arrive
// on — which is why entry and dialer are separate questions here.
func (e *Engine) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	// Reverse mode: the Foreign server dials, the Iran server listens. Which end
	// the VPN clients arrive on is a separate question from which end opens the
	// carrier, so both are asked separately here.
	if e.isDialer {
		n := warmPool(e.cfg.Pool)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); e.carrierWorker(ctx) }()
		}
	} else {
		wg.Add(1)
		go func() { defer wg.Done(); e.acceptCarriers(ctx) }()
	}
	if e.isEntry {
		wg.Add(1)
		go func() { defer wg.Done(); e.serveClients(ctx) }()
	}

	e.log.Info("openvpn engine started role=%s transport=%s openvpn_port=%d entry=%v dialer=%v (%d warm carriers, %d KiB relay)",
		e.cfg.Role, e.cfg.Transport, e.port, e.isEntry, e.isDialer, warmPool(e.cfg.Pool), relayBuf>>10)

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

// start is the one byte the entry sends down a parked carrier to say "a client
// has arrived, open the VPN now".
//
// The exit must not dial the OpenVPN server when the carrier is established,
// only when a client actually appears — otherwise every warm carrier would hold
// an idle connection open against OpenVPN, and OpenVPN would count them as
// clients.
const startByte = 0x01

// ---- exit side (the carrier's dialer) ----------------------------------------

// carrierWorker keeps exactly one carrier parked at the entry. When the entry
// uses it, the worker opens the next — so the warm pool stays the size it was
// asked to be, with no leaked dials.
func (e *Engine) carrierWorker(ctx context.Context) {
	backoff := 250 * time.Millisecond
	for ctx.Err() == nil {
		raw, err := e.dialer.Dial(ctx)
		if err != nil {
			e.log.Warn("carrier dial: %v", err)
			if !sleepCtx(ctx, &backoff) {
				return
			}
			continue
		}
		nettune.Apply(raw, e.tune)
		sc, err := crypto.ClientHandshake(raw, e.cipher)
		if err != nil {
			_ = raw.Close()
			e.log.Warn("carrier handshake: %v", err)
			if !sleepCtx(ctx, &backoff) {
				return
			}
			continue
		}
		backoff = 250 * time.Millisecond
		e.up.Store(true)
		// Blocks until the entry claims this carrier, or it dies.
		e.awaitClient(ctx, sc)
	}
}

// awaitClient parks one carrier until the entry says a client has arrived, then
// connects it to the local OpenVPN server.
func (e *Engine) awaitClient(ctx context.Context, sc *crypto.SecureConn) {
	defer sc.Close()
	stop := context.AfterFunc(ctx, func() { _ = sc.Close() })
	defer stop()

	// No deadline: the carrier is deliberately parked, possibly for hours.
	var b [1]byte
	if _, err := io.ReadFull(sc, b[:]); err != nil {
		return // the entry closed it, or the path died; the worker dials again
	}
	if b[0] != startByte {
		e.log.Warn("carrier sent %#x instead of a start byte — dropping it", b[0])
		return
	}

	target := net.JoinHostPort(e.exitHost, itoa(e.port))
	local, err := net.DialTimeout("tcp", target, exitDialTO)
	if err != nil {
		atomic.AddUint64(&e.stats.refused, 1)
		e.log.Warn("cannot reach the OpenVPN server at %s: %v — is it running and listening on TCP?", target, err)
		return
	}
	defer local.Close()
	e.tuneVPNSocket(local)

	atomic.AddUint64(&e.stats.accepted, 1)
	atomic.AddUint64(&e.stats.connected, 1)
	// Named from the client's point of view on both servers, so the two logs
	// read the same way round.
	e.relay(local, sc, &e.stats.toClient, &e.stats.toExit)
}

// ---- entry side (the carrier's listener) -------------------------------------

// acceptCarriers takes authenticated carriers and parks them ready for a client.
//
// The handshake runs in its own goroutine: doing it on the accept path would let
// one peer that connects and says nothing hold up every real carrier behind it,
// which is a stall this project has been bitten by before.
func (e *Engine) acceptCarriers(ctx context.Context) {
	for ctx.Err() == nil {
		raw, err := e.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			e.log.Warn("carrier accept: %v", err)
			continue
		}
		nettune.Apply(raw, e.tune)
		go func() {
			sc, err := crypto.ServerHandshake(raw, e.cipher)
			if err != nil {
				_ = raw.Close()
				e.log.Warn("carrier handshake from %s: %v", raw.RemoteAddr(), err)
				return
			}
			e.up.Store(true)
			atomic.AddInt64(&e.stats.ready, 1)
			select {
			case e.parked <- sc:
			case <-ctx.Done():
				atomic.AddInt64(&e.stats.ready, -1)
				_ = sc.Close()
			}
		}()
	}
}

func (e *Engine) serveClients(ctx context.Context) {
	var lc net.ListenConfig
	var ln net.Listener
	backoff := time.Second
	warned := false
	for {
		var err error
		ln, err = lc.Listen(ctx, "tcp", ":"+itoa(e.port))
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return
		}
		if !warned {
			e.log.Error("cannot bind the OpenVPN port %d yet (%v) — clients cannot connect until it is free; retrying", e.port, err)
			warned = true
		}
		if !sleepCtx(ctx, &backoff) {
			return
		}
	}
	defer ln.Close()
	go func() { <-ctx.Done(); _ = ln.Close() }()

	e.log.Info("listening for OpenVPN clients on tcp/%d", e.port)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		atomic.AddUint64(&e.stats.accepted, 1)
		go e.carryClient(ctx, c)
	}
}

// carryClient hands one OpenVPN connection its own carrier.
func (e *Engine) carryClient(ctx context.Context, c net.Conn) {
	defer c.Close()
	e.tuneVPNSocket(c)

	start := time.Now()
	sc := e.claimCarrier(ctx)
	atomic.StoreInt64(&e.stats.waitMs, time.Since(start).Milliseconds())
	if sc == nil {
		atomic.AddUint64(&e.stats.refused, 1)
		// Refusing at once is deliberate. OpenVPN retries a refused connection
		// promptly; holding it open only burns the client's whole connect
		// timeout before it can try again.
		e.log.Warn("no carrier ready for an OpenVPN client — refusing so the client retries")
		return
	}
	defer sc.Close()

	// Wake the far end: only now does it open the real OpenVPN connection.
	if _, err := sc.Write([]byte{startByte}); err != nil {
		atomic.AddUint64(&e.stats.refused, 1)
		e.log.Warn("carrier died before it could be used: %v", err)
		return
	}
	atomic.AddUint64(&e.stats.connected, 1)
	e.relay(c, sc, &e.stats.toExit, &e.stats.toClient)
}

// claimCarrier takes a parked carrier, waiting briefly if none is ready.
//
// The wait is short on purpose: a client that cannot be served in a couple of
// seconds is better told so, because OpenVPN's own retry is faster and cleaner
// than anything achieved by making it wait.
func (e *Engine) claimCarrier(ctx context.Context) *crypto.SecureConn {
	deadline := time.NewTimer(claimWait)
	defer deadline.Stop()
	select {
	case sc := <-e.parked:
		atomic.AddInt64(&e.stats.ready, -1)
		return sc
	case <-deadline.C:
		return nil
	case <-ctx.Done():
		return nil
	}
}

// ---- the relay ---------------------------------------------------------------

// tuneVPNSocket sets the options that matter on a VPN-carrying socket.
//
// TCP_NODELAY above all: OpenVPN's control channel is small writes, and Nagle
// holds a small write until the previous one is acknowledged — a whole
// round-trip of delay added to every handshake step, on a path already chosen
// because it is slow.
func (e *Engine) tuneVPNSocket(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		// Keepalive so a client that vanishes without a FIN — a laptop closing,
		// a NAT expiring — is eventually reaped instead of holding a carrier
		// connection open for nothing.
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

// relay moves bytes both ways until either side finishes, then closes both.
//
// Both directions must end together. Leaving one running after the other has
// stopped is how a half-closed VPN connection survives as a goroutine holding a
// carrier connection open, and enough of those is a server that slowly stops
// accepting anything.
func (e *Engine) relay(vpn net.Conn, link io.ReadWriteCloser, up, down *uint64) {
	atomic.AddInt64(&e.stats.active, 1)
	defer atomic.AddInt64(&e.stats.active, -1)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n := e.pipe(link, vpn)
		atomic.AddUint64(up, n)
		// Stopping the other direction as soon as this one ends is what keeps
		// the pair symmetrical; without it the peer waits out a timeout.
		_ = vpn.Close()
		_ = link.Close()
	}()
	go func() {
		defer wg.Done()
		n := e.pipe(vpn, link)
		atomic.AddUint64(down, n)
		_ = vpn.Close()
		_ = link.Close()
	}()
	wg.Wait()
}

// pipe copies one direction using a small buffer.
//
// io.Copy would allocate 32 KiB per call and, more importantly, the buffer size
// is the point: see relayBuf. Nothing here reads ahead — one buffer is filled,
// written, and only then is the next read issued, so the bytes in flight
// between the two TCP layers stay bounded by exactly one buffer per direction.
func (e *Engine) pipe(dst io.Writer, src io.Reader) uint64 {
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp

	var total uint64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total
			}
			total += uint64(n)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return total
			}
			return total
		}
	}
}

// ---- health and stats ---------------------------------------------------------

func (e *Engine) Healthy() bool { return e.up.Load() }

// Stats is what the dashboard and the health check read.
type Stats struct {
	Role          string `json:"role"`
	Transport     string `json:"transport"`
	OpenVPNPort   int    `json:"openvpn_port"`
	Accepted      uint64 `json:"vpn_connections"`
	Connected     uint64 `json:"vpn_connected"`
	Refused       uint64 `json:"vpn_refused"`
	Active        int64  `json:"vpn_active"`
	BytesToExit   uint64 `json:"bytes_to_exit"`
	BytesToClient uint64 `json:"bytes_to_client"`
	WaitMs        int64  `json:"client_wait_ms"` // how long the last client waited for a carrier
	CarriersReady int64  `json:"carriers_ready"` // warm carriers available right now
	RelayBufBytes int    `json:"relay_buffer_bytes"`
}

func (e *Engine) Snapshot() any {
	return Stats{
		Role:          e.cfg.Role,
		Transport:     e.cfg.Transport,
		OpenVPNPort:   e.port,
		Accepted:      atomic.LoadUint64(&e.stats.accepted),
		Connected:     atomic.LoadUint64(&e.stats.connected),
		Refused:       atomic.LoadUint64(&e.stats.refused),
		Active:        atomic.LoadInt64(&e.stats.active),
		BytesToExit:   atomic.LoadUint64(&e.stats.toExit),
		BytesToClient: atomic.LoadUint64(&e.stats.toClient),
		WaitMs:        atomic.LoadInt64(&e.stats.waitMs),
		CarriersReady: atomic.LoadInt64(&e.stats.ready),
		RelayBufBytes: relayBuf,
	}
}

// ---- small helpers ------------------------------------------------------------

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func sleepCtx(ctx context.Context, b *time.Duration) bool {
	t := time.NewTimer(*b)
	defer t.Stop()
	if *b < 5*time.Second {
		*b *= 2
	}
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [12]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		b[n] = '-'
	}
	return string(b[n:])
}
