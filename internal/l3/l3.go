// Package l3 implements the L3 TUN tunnel engine: it moves raw IP packets
// between a local multi-queue TUN device and the peer over N authenticated,
// encrypted TCP links (one per queue).
//
// Design (pengutunnel-style):
//   - N = pool queues/links. The kernel distributes flows across TUN queues
//     (per-flow, so ordering is preserved); each queue is paired 1:1 with a link.
//   - One persistent reader per queue feeds a bounded channel, so links can come
//     and go (reconnects) without leaking a blocked TUN read.
//   - TX batches packets into as few AEAD frames as possible.
//   - An application-level heartbeat detects dead links; the dialing side
//     reconnects with backoff, the listening side frees the slot.
package l3

import (
	"bufio"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/crypto"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/nettune"
	"github.com/emergency-tunnel/et/internal/sysinfo"
	"github.com/emergency-tunnel/et/internal/transport"
	"github.com/emergency-tunnel/et/internal/tun"
)

// Engine is one L3 tunnel instance.
type Engine struct {
	cfg      *config.Config
	log      *logx.Logger
	cipher   string
	queues   int
	isDialer bool

	dialer   transport.Dialer
	listener transport.Listener

	sndbuf, rcvbuf int
	batchSize      int
	channelSize    int
	pktLen         int // max bytes read from a TUN queue
	hbInterval     time.Duration
	hbTimeout      time.Duration
	nowSec         func() int64

	pool sync.Pool // *[]byte packet buffers

	stats struct {
		liveLinks  int64
		txPackets  uint64
		rxPackets  uint64
		txBytes    uint64
		rxBytes    uint64
		reconnects uint64
	}
}

// New builds an L3 engine from validated config.
func New(cfg *config.Config, log *logx.Logger) (*Engine, error) {
	tr, err := transport.Get(cfg.Transport)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		cfg:         cfg,
		log:         log,
		cipher:      cfg.Cipher,
		queues:      cfg.Pool,
		isDialer:    cfg.IsDialer(),
		batchSize:   orDefault(cfg.BatchSize, 32),
		channelSize: orDefault(cfg.ChannelSize, 512),
		pktLen:      cfg.MTU + 4,
		hbInterval:  time.Duration(orDefault(cfg.HeartbeatInterval, 10)) * time.Second,
		hbTimeout:   time.Duration(orDefault(cfg.HeartbeatTimeout, 25)) * time.Second,
		nowSec:      func() int64 { return time.Now().Unix() },
	}
	if e.queues < 1 {
		e.queues = 1
	}
	e.pool.New = func() any { b := make([]byte, e.pktLen); return &b }
	e.sndbuf, e.rcvbuf = nettune.BufSizes(cfg.Profile, cfg.SoSndbuf, cfg.SoRcvbuf)

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

// Run opens the TUN device, establishes the links, and pumps packets until ctx
// is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	dev, err := tun.Open(tun.Config{
		Name:     e.cfg.TunIface,
		Address:  e.cfg.TunIP,
		Address6: e.cfg.TunIP6,
		MTU:      e.cfg.MTU,
		Queues:   e.queues,
	})
	if err != nil {
		return err
	}
	defer dev.Close()

	if cores := sysinfo.EffectiveCPUs(); e.queues > cores {
		e.log.Warn("pool=%d queues but only %d usable cores — extra queues share cores; consider pool≈%d on both ends",
			e.queues, cores, cores)
	}
	e.log.Info("TUN tunnel starting: iface=%s addr=%s mtu=%d queues=%d cipher=%s role=%s dialer=%v",
		dev.Name(), e.cfg.TunIP, dev.MTU(), e.queues, e.cfg.Cipher, e.cfg.Role, e.isDialer)
	e.log.Debug("tuning: batch=%d channel=%d hb=%s/%s sndbuf=%d rcvbuf=%d",
		e.batchSize, e.channelSize, e.hbInterval, e.hbTimeout, e.sndbuf, e.rcvbuf)

	// One persistent reader per queue feeds a bounded channel. This survives
	// link reconnects without leaking a blocked TUN read.
	txChans := make([]chan []byte, e.queues)
	var readers sync.WaitGroup
	for i := 0; i < e.queues; i++ {
		txChans[i] = make(chan []byte, e.channelSize)
		readers.Add(1)
		go func(i int) { defer readers.Done(); e.queueReader(ctx, dev.Queues()[i], txChans[i]) }(i)
	}

	var pumps sync.WaitGroup
	if e.isDialer {
		for i := 0; i < e.queues; i++ {
			i := i
			pumps.Add(1)
			go func() { defer pumps.Done(); e.clientQueue(ctx, dev.Queues()[i], txChans[i], i) }()
		}
	} else {
		pumps.Add(1)
		go func() { defer pumps.Done(); e.serverAccept(ctx, dev, txChans) }()
	}

	<-ctx.Done()
	if e.dialer != nil {
		_ = e.dialer.Close()
	}
	if e.listener != nil {
		_ = e.listener.Close()
	}
	dev.Close() // unblocks the queue readers
	pumps.Wait()
	readers.Wait()
	return nil
}

// logConnected emits the single, clear "connected" line when the first link of
// the tunnel comes up (called on the 0->1 live-link transition).
func (e *Engine) logConnected(id int) {
	local := ipOnly(e.cfg.TunIP)
	peer := e.cfg.PeerTunIP
	if peer == "" {
		peer = "peer"
	}
	e.log.Info("Tunnel connected successfully: %s %s <-> %s %s",
		e.roleName(true), local, e.roleName(false), peer)
}

// roleName returns a friendly name for this host (self=true) or the peer.
func (e *Engine) roleName(self bool) string {
	iran := e.cfg.Role == config.RoleIran
	if !self {
		iran = !iran
	}
	if iran {
		return "Iran Server"
	}
	return "Foreign Server"
}

func ipOnly(cidr string) string {
	if i := strings.IndexByte(cidr, '/'); i >= 0 {
		return cidr[:i]
	}
	return cidr
}

// queueReader is the single goroutine allowed to block on a TUN queue's Read.
// It lives for the whole run; packets are dropped only if the channel is full
// (i.e. the link is down), which is harmless for L3 (upper layers retransmit).
func (e *Engine) queueReader(ctx context.Context, q queue, ch chan<- []byte) {
	for {
		bp := e.pool.Get().(*[]byte)
		n, err := q.Read((*bp)[:e.pktLen])
		if err != nil {
			e.pool.Put(bp)
			return // device closed
		}
		// Copy into a right-sized slice we hand off; recycle the read buffer.
		pkt := make([]byte, n)
		copy(pkt, (*bp)[:n])
		e.pool.Put(bp)
		select {
		case ch <- pkt:
		case <-ctx.Done():
			return
		default:
			// Link down / consumer slow: drop rather than block the reader.
		}
	}
}

// clientQueue keeps a link dialed for its queue and pumps, reconnecting on loss.
func (e *Engine) clientQueue(ctx context.Context, q queue, ch <-chan []byte, id int) {
	backoff := time.Second
	for ctx.Err() == nil {
		raw, err := e.dialer.Dial(ctx)
		if err != nil {
			e.log.Warn("queue %d dial: %v", id, err)
			if !sleepCtx(ctx, &backoff) {
				return
			}
			continue
		}
		nettune.TuneConn(raw, e.sndbuf, e.rcvbuf)
		link, err := crypto.ClientHandshake(raw, e.cipher)
		if err != nil {
			_ = raw.Close()
			e.log.Warn("queue %d handshake: %v", id, err)
			if !sleepCtx(ctx, &backoff) {
				return
			}
			continue
		}
		backoff = time.Second
		e.pump(ctx, q, ch, link, id)
		atomic.AddUint64(&e.stats.reconnects, 1)
	}
}

// serverAccept assigns each inbound link to a free queue slot and pumps it.
func (e *Engine) serverAccept(ctx context.Context, dev *tun.Device, txChans []chan []byte) {
	free := make(chan int, e.queues)
	for i := 0; i < e.queues; i++ {
		free <- i
	}
	var wg sync.WaitGroup
	for ctx.Err() == nil {
		raw, err := e.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			e.log.Warn("accept: %v", err)
			continue
		}
		var slot int
		select {
		case slot = <-free:
		default:
			_ = raw.Close() // all queues occupied
			continue
		}
		nettune.TuneConn(raw, e.sndbuf, e.rcvbuf)
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			defer func() { free <- slot }()
			link, err := crypto.ServerHandshake(raw, e.cipher)
			if err != nil {
				_ = raw.Close()
				e.log.Warn("handshake from %s: %v", raw.RemoteAddr(), err)
				return
			}
			e.pump(ctx, dev.Queues()[slot], txChans[slot], link, slot)
		}(slot)
	}
	wg.Wait()
}

// pump bridges one TUN queue with one link until either side fails or the
// heartbeat times out.
func (e *Engine) pump(ctx context.Context, q queue, ch <-chan []byte, link *crypto.SecureConn, id int) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer link.Close()

	var lastRecv atomic.Int64
	lastRecv.Store(e.nowSec())
	if atomic.AddInt64(&e.stats.liveLinks, 1) == 1 {
		e.logConnected(id)
	}
	defer func() {
		if atomic.AddInt64(&e.stats.liveLinks, -1) == 0 && ctx.Err() == nil {
			e.log.Warn("TUN tunnel disconnected — all links down, reconnecting…")
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); defer cancel(); e.tunToLink(ctx, ch, link) }()
	go func() { defer wg.Done(); defer cancel(); e.linkToTun(ctx, q, link, &lastRecv) }()
	e.heartbeatMonitor(ctx, cancel, &lastRecv, id) // blocks until ctx is done
	wg.Wait()
}

// tunToLink consumes packets from the queue channel, batches them, and writes
// to the link. It also emits periodic heartbeats.
func (e *Engine) tunToLink(ctx context.Context, ch <-chan []byte, link *crypto.SecureConn) {
	batch := make([]byte, 0, e.batchSize*e.pktLen)
	pending := 0

	hb := time.NewTicker(e.hbInterval)
	defer hb.Stop()
	const flushEvery = 2 * time.Millisecond
	flush := time.NewTimer(flushEvery)
	if !flush.Stop() {
		<-flush.C
	}
	defer flush.Stop()

	send := func() bool {
		if len(batch) == 0 {
			return true
		}
		if _, err := link.Write(batch); err != nil {
			return false
		}
		atomic.AddUint64(&e.stats.txPackets, uint64(pending))
		atomic.AddUint64(&e.stats.txBytes, uint64(len(batch)))
		batch = batch[:0]
		pending = 0
		return true
	}

	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-ch:
			batch = appendPacket(batch, pkt)
			pending++
			if pending == 1 {
				flush.Reset(flushEvery)
			}
			if pending >= e.batchSize || len(batch) >= 60*1024 {
				if !flush.Stop() {
					select {
					case <-flush.C:
					default:
					}
				}
				if !send() {
					return
				}
			}
		case <-flush.C:
			if !send() {
				return
			}
		case <-hb.C:
			batch = appendHeartbeat(batch)
			if !send() {
				return
			}
		}
	}
}

// linkToTun reads datagrams and writes packets to the queue.
func (e *Engine) linkToTun(ctx context.Context, q queue, link *crypto.SecureConn, lastRecv *atomic.Int64) {
	stop := context.AfterFunc(ctx, func() { _ = link.SetReadDeadline(time.Now()) })
	defer stop()

	r := bufio.NewReaderSize(link, 64*1024)
	buf := make([]byte, maxPacket)
	for {
		n, hb, err := readDatagram(r, buf)
		if err != nil {
			return
		}
		lastRecv.Store(e.nowSec())
		if hb {
			continue
		}
		if _, err := q.Write(buf[:n]); err != nil {
			return
		}
		atomic.AddUint64(&e.stats.rxPackets, 1)
		atomic.AddUint64(&e.stats.rxBytes, uint64(n))
	}
}

// heartbeatMonitor cancels the pump if no datagram arrives within hbTimeout.
func (e *Engine) heartbeatMonitor(ctx context.Context, cancel context.CancelFunc, lastRecv *atomic.Int64, id int) {
	t := time.NewTicker(e.hbInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if time.Since(time.Unix(lastRecv.Load(), 0)) > e.hbTimeout {
				e.log.Warn("queue %d: heartbeat timeout, cycling link", id)
				cancel()
				return
			}
		}
	}
}

// Stats is a point-in-time snapshot.
type Stats struct {
	LiveLinks  int64  `json:"live_links"`
	TxPackets  uint64 `json:"tx_packets"`
	RxPackets  uint64 `json:"rx_packets"`
	TxBytes    uint64 `json:"tx_bytes"`
	RxBytes    uint64 `json:"rx_bytes"`
	Reconnects uint64 `json:"reconnects"`
}

// Snapshot returns current counters (as any, to satisfy the shared engine
// interface used by the health endpoint).
func (e *Engine) Snapshot() any {
	return Stats{
		LiveLinks:  atomic.LoadInt64(&e.stats.liveLinks),
		TxPackets:  atomic.LoadUint64(&e.stats.txPackets),
		RxPackets:  atomic.LoadUint64(&e.stats.rxPackets),
		TxBytes:    atomic.LoadUint64(&e.stats.txBytes),
		RxBytes:    atomic.LoadUint64(&e.stats.rxBytes),
		Reconnects: atomic.LoadUint64(&e.stats.reconnects),
	}
}

// queue is the subset of *os.File used by the pump (satisfied by TUN queues).
type queue interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
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
