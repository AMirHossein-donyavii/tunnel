// Package l3 implements the L3 TUN tunnel engine: it moves raw IP packets
// between a local multi-queue TUN device and the peer over N authenticated,
// encrypted links (one per queue).
//
// Design:
//   - N = pool queues/links. The kernel distributes flows across TUN queues
//     (per-flow, so ordering is preserved); each queue is paired 1:1 with a link.
//   - One persistent reader per queue feeds a scheduler (see sched.go), so links
//     can come and go without leaking a blocked TUN read, and so a bulk transfer
//     can never park an interactive packet behind its backlog.
//   - TX drains the scheduler into as few AEAD frames and syscalls as possible.
//     Batching is opportunistic rather than timer-driven: the batch is flushed
//     the moment the queue runs dry, so a single packet on an idle tunnel is
//     sent immediately while a saturated tunnel fills whole frames.
//   - A control channel measures true link RTT and detects dead links; the
//     dialing side reconnects with backoff, the listening side frees the slot.
package l3

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/firewall"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/netq"
	"github.com/emergency-tunnel/et/internal/nettune"
	"github.com/emergency-tunnel/et/internal/sysinfo"
	"github.com/emergency-tunnel/et/internal/transport"
	"github.com/emergency-tunnel/et/internal/tun"
)

// Engine is one L3 (TUN) tunnel instance.
type Engine struct {
	cfg      *config.Config
	log      *logx.Logger
	cipher   string
	mode     string // carrier: tcp | udp | icmp | bip
	queues   int
	isDialer bool

	ldialer   linkDialer
	llistener linkListener

	sndbuf, rcvbuf int
	batchSize      int
	channelSize    int
	stripe         bool // spread one queue's packets over every link
	pktLen         int // max bytes read from a TUN queue
	hbInterval     time.Duration
	hbTimeout      time.Duration
	nowSec         func() int64

	pool *bufPool // recycled packet buffers

	stats struct {
		liveLinks  int64
		txPackets  uint64
		rxPackets  uint64
		txBytes    uint64
		rxBytes    uint64
		reconnects uint64
		badFrames  uint64
		// tunWriteErrs counts packets the TUN device refused. They used to be
		// invisible, and they used to end the link — see linkToTun.
		tunWriteErrs uint64
		rttNs        int64 // EWMA of the measured link RTT
	}
	qstats qstats
}

// maxTunWriteErrs bounds how many consecutive packets the TUN device may refuse
// before the link is cycled. A handful is an overfull device queue or one
// malformed packet; hundreds in a row is a device that has gone away, and
// carrying on would spin against it.
const maxTunWriteErrs = 128

// safeDatagramMTU is the largest inner MTU that leaves room for the AEAD +
// L4/IP wrapper to fit a ~1400-byte path (the Iranian underlays SPF/ICMP/UDP
// carriers target). A larger inner packet becomes a DF datagram that blackholes
// with no PMTUD across the tunnel.
const safeDatagramMTU = 1320

// New builds a TUN engine from validated config.
func New(cfg *config.Config, log *logx.Logger) (*Engine, error) {
	// Datagram carriers (udp/icmp/bip and every SPF profile) wrap each inner
	// packet in one carrier datagram, so the inner MTU must leave header room.
	// The reliable tcp carrier re-segments and is unaffected.
	if datagramCarrier(cfg) && cfg.MTU > safeDatagramMTU {
		log.Warn("mtu %d is too high for a datagram carrier — wrapped packets would exceed a ~1400-byte path and blackhole; clamping to %d (set mtu=%d to silence)",
			cfg.MTU, safeDatagramMTU, safeDatagramMTU)
		cfg.MTU = safeDatagramMTU
	}
	e := &Engine{
		cfg:      cfg,
		log:      log,
		cipher:   cfg.Cipher,
		mode:     cfg.TunMode,
		queues:   cfg.Pool,
		isDialer: cfg.IsDialer(),
		// A 64-packet batch fills the ~60 KiB TCP frame (fewer frames/syscalls).
		// The per-queue ring is only a burst absorber, not a standing queue —
		// CoDel (sched.go) keeps its actual occupancy near 5 ms of drain time
		// regardless of the configured depth.
		batchSize:   orDefault(cfg.BatchSize, 64),
		channelSize: orDefault(cfg.ChannelSize, channelDefault(cfg.Profile)),
		stripe:      cfg.Stripe != config.StripeFlow,
		pktLen:      cfg.MTU + 4,
		hbInterval:  time.Duration(orDefault(cfg.HeartbeatInterval, config.DefaultHeartbeatSec)) * time.Second,
		hbTimeout:   time.Duration(orDefault(cfg.HeartbeatTimeout, config.DefaultHeartbeatTimeoutSec)) * time.Second,
		nowSec:      func() int64 { return time.Now().Unix() },
	}
	if cfg.IsSPF() {
		e.mode = "spf"
	}
	if e.mode == "" {
		e.mode = config.TunModeTCP
	}
	// TUN queue count is TunQueues if set, else Pool. It MUST match on both
	// servers: the kernel fans flows across all queues, and a queue with no peer
	// link drops every flow hashed to it.
	if cfg.TunQueues > 0 {
		e.queues = cfg.TunQueues
	}
	if e.queues < 1 {
		e.queues = 1
	}
	// Duplication of small frames is this tunnel's choice, not a build-time
	// constant: it buys resilience on a path that drops small packets and costs
	// bandwidth on a path that does not. See config.DupThreshold.
	SetDupThreshold(cfg.DupBytes())
	e.pool = newBufPool(e.pktLen)
	e.sndbuf, e.rcvbuf = nettune.BufSizes(cfg.Profile, cfg.SoSndbuf, cfg.SoRcvbuf)

	if err := e.buildCarrier(cfg, log); err != nil {
		return nil, err
	}
	return e, nil
}

// buildCarrier constructs the dialer or listener for the selected TUN mode.
func (e *Engine) buildCarrier(cfg *config.Config, log *logx.Logger) error {
	tune := nettune.LinkOptions(cfg.Profile, cfg.SoSndbuf, cfg.SoRcvbuf)
	switch e.mode {
	case config.TunModeUDP:
		if e.isDialer {
			e.ldialer = &udpLinkDialer{addr: net.JoinHostPort(cfg.Peer, strconv.Itoa(cfg.TunnelPort)), cipher: e.cipher, sndbuf: e.sndbuf, rcvbuf: e.rcvbuf}
		} else {
			l, err := newUDPListener(cfg.TunnelPort, e.sndbuf, e.rcvbuf, e.cipher)
			if err != nil {
				return err
			}
			e.llistener = l
		}
	case config.TunModeICMP, config.TunModeBIP:
		d, l, err := newICMPCarrier(e.mode, cfg, e.isDialer, e.cipher, log)
		if err != nil {
			return err
		}
		e.ldialer, e.llistener = d, l
	case config.TunModeIPIP, config.TunModeGRE:
		d, l, err := newIPXCarrier(e.mode, cfg, e.isDialer, e.cipher, log)
		if err != nil {
			return err
		}
		e.ldialer, e.llistener = d, l
	case "spf":
		d, l, err := newSPFRawCarrier(cfg, e.isDialer, e.cipher)
		if err != nil {
			return err
		}
		e.ldialer, e.llistener = d, l
		log.Info("SPF spoof mapping initialized successfully: profile=%s src=%s dst=%s",
			cfg.SpfProfile, cfg.SpoofSrcIP, cfg.SpoofDstIP)
	default: // tcp
		tr, err := transport.Get("tcp")
		if err != nil {
			return err
		}
		if e.isDialer {
			d, err := tr.NewDialer(cfg, log)
			if err != nil {
				return err
			}
			e.ldialer = &tcpLinkDialer{d: d, cipher: e.cipher, tune: tune}
		} else {
			l, err := tr.NewListener(cfg, log)
			if err != nil {
				return err
			}
			e.llistener = &tcpLinkListener{l: l, cipher: e.cipher, tune: tune, q: newHandshakeQueue()}
		}
	}
	return nil
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
	label := "TUN"
	carrier := e.mode
	if e.cfg.IsSPF() {
		label, carrier = "SPF", e.cfg.SpfProfile+"+spoof"
	}
	stripe := "flow (one link per queue)"
	if e.stripe {
		stripe = "packet (every link carries every queue)"
	}
	e.log.Info("%s tunnel starting: iface=%s addr=%s mtu=%d queues=%d carrier=%s cipher=%s role=%s dialer=%v stripe=%s",
		label, dev.Name(), e.cfg.TunIP, dev.MTU(), e.queues, carrier, e.cfg.Cipher, e.cfg.Role, e.isDialer, stripe)
	e.log.Debug("tuning: batch=%d channel=%d hb=%s/%s sndbuf=%d rcvbuf=%d",
		e.batchSize, e.channelSize, e.hbInterval, e.hbTimeout, e.sndbuf, e.rcvbuf)

	// Kernel rules this tunnel owns: the DNAT set for forwarded VPN/service
	// ports, and — for the SPF tcp carrier — the drop that stops the kernel
	// resetting its own link. Applied once the interface is up and torn down on
	// shutdown. A failure here is logged but never stops the data plane.
	//
	// The SPF rules are needed whether or not anything is forwarded, so this can
	// not be gated on forwarding alone.
	if firewall.Enabled(e.cfg) || firewall.SPFNeedsRSTDrop(e.cfg) {
		if err := firewall.Apply(e.cfg, dev.Name(), e.log); err != nil {
			e.log.Warn("firewall rules not applied (tunnel continues): %v", err)
		}
		defer firewall.Remove(e.cfg, e.log)
	}

	// One persistent reader per queue feeds a priority + AQM scheduler. This
	// survives link reconnects without leaking a blocked TUN read.
	//
	// Whether those readers feed one scheduler or one each is the whole of link
	// striping. With one shared queue every link drains every TUN queue, so a
	// single TCP stream is carried by all the links at once instead of the one
	// its flow hashed onto; with a queue each, the pairing is fixed. The shared
	// queue is sized to the same total depth as the separate ones would have
	// been, so striping changes where packets can go, not how many may wait.
	txQueues := e.buildTxQueues()
	var readers sync.WaitGroup
	for i := 0; i < e.queues; i++ {
		readers.Add(1)
		go func(i int) { defer readers.Done(); e.queueReader(ctx, dev.Queues()[i], txQueues[i]) }(i)
	}

	go e.healthReport(ctx)

	var pumps sync.WaitGroup
	if e.isDialer {
		for i := 0; i < e.queues; i++ {
			i := i
			pumps.Add(1)
			go func() { defer pumps.Done(); e.clientQueue(ctx, dev.Queues()[i], txQueues[i], i) }()
		}
	} else {
		pumps.Add(1)
		go func() { defer pumps.Done(); e.serverAccept(ctx, dev, txQueues) }()
	}

	<-ctx.Done()
	if e.ldialer != nil {
		_ = e.ldialer.Close()
	}
	if e.llistener != nil {
		_ = e.llistener.Close()
	}
	dev.Close() // unblocks the queue readers
	pumps.Wait()
	readers.Wait()
	return nil
}

// healthReport writes one line a minute naming every way this tunnel is losing
// packets, and stays silent while there is nothing to say.
//
// "The tunnel is unstable" was unanswerable: reconnects, packets the TUN device
// refused, frames the carrier socket refused, datagrams dropped because a link
// was not draining, and AQM drops all produce the same symptom and have five
// different fixes. Each was counted and none was ever shown. The line reports
// what changed since the last one, so a rate is readable directly rather than
// being the difference of two totals nobody recorded.
func (e *Engine) healthReport(ctx context.Context) {
	const every = time.Minute
	t := time.NewTicker(every)
	defer t.Stop()

	var prev, prev0 Stats
	prev = e.Snapshot().(Stats)
	prev0 = prev
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cur := e.Snapshot().(Stats)
		d := func(now, before uint64) uint64 {
			if now < before {
				return 0
			}
			return now - before
		}
		reconnects := d(cur.Reconnects, prev.Reconnects)
		tunErrs := d(cur.TunWriteErrors, prev.TunWriteErrors)
		sockErrs := d(cur.CarrierWriteErrors, prev.CarrierWriteErrors)
		demux := d(cur.CarrierDropped, prev.CarrierDropped)
		aqm := d(cur.AQMDropped, prev.AQMDropped)
		full := d(cur.QueueFull, prev.QueueFull)
		stale := d(cur.StaleDropped, prev.StaleDropped)
		bad := d(cur.BadFrames, prev.BadFrames)
		authBad := d(cur.AuthFailed, prev.AuthFailed)
		ctlBad := d(cur.BadControl, prev.BadControl)
		strangers := d(cur.NotOurs, prev.NotOurs)
		dupIn := d(cur.DupDropped, prev.DupDropped)
		dupOut := d(cur.DupSent, prev.DupSent)
		prev, prev0 = cur, prev

		txB := d(cur.TxBytes, prev0.TxBytes)
		rxB := d(cur.RxBytes, prev0.RxBytes)

		// A minute in which the tunnel carried nothing used to print nothing,
		// because every counter was zero — which is the same silence as a minute
		// in which nobody used it. Those are opposite situations and the second
		// one is the failure that matters most: links up, heartbeats flowing,
		// and not a byte of traffic getting through.
		//
		// So the line always appears while there is a live link, and it always
		// carries the throughput. Nothing to report now reads as
		// "tx=0 rx=0 links=4", which is unmistakable.
		quiet := reconnects == 0 && tunErrs == 0 && sockErrs == 0 && demux == 0 &&
			aqm == 0 && full == 0 && stale == 0 && bad == 0
		if quiet && cur.LiveLinks == 0 {
			continue // nothing is connected; the pump logs that itself
		}
		// Both duplicate counters are reported as they are. They used to be
		// subtracted from each other to guess how many copies the path had
		// needed, which is not a subtraction that means anything: one counts
		// copies this side SENT and the other counts copies this side RECEIVED
		// and discarded. Those are different directions at different rates, and
		// on an unsigned counter the subtraction wrapped — which is how a health
		// line came to report 18446744073709549315.
		dup := ""
		if dupOut > 0 || dupIn > 0 {
			dup = fmt.Sprintf(" dup_sent=%d dup_recv=%d", dupOut, dupIn)
		}
		// auth_failed is the one number here that names a cause rather than a
		// symptom, so when it is non-zero it is spelled out in words. A frame
		// only reaches the AEAD after the carrier has matched the peer's
		// address, this tunnel's tag and this link's id: it did come from the
		// peer, addressed to this link, and would not open. Two ends that
		// handshake and then cannot read each other is a version or key
		// mismatch, and there is nothing else it can be — but it spent a week
		// looking like a generic "bad_frames" count next to a rate of zero.
		if authBad > 0 && rxB == 0 {
			e.log.Error("%d datagrams from the peer failed to decrypt and NOTHING was received: "+
				"the two ends completed a handshake and cannot read each other. Check that both "+
				"servers run the same core version (et-core version) and the same token.", authBad)
		}
		e.log.Info("last %s: tx=%s rx=%s links=%d rtt=%.1fms | reconnects=%d "+
			"tun_refused=%d socket_refused=%d demux_dropped=%d aqm_dropped=%d "+
			"queue_full=%d stale=%d auth_failed=%d bad_control=%d not_ours=%d queued=%d%s",
			every, rate(txB, every), rate(rxB, every), cur.LiveLinks, cur.RTTMs,
			reconnects, tunErrs, sockErrs, demux, aqm, full, stale,
			authBad, ctlBad, strangers, cur.QueueDepth, dup)
	}
}

// rate renders bytes over a window as a human-readable bit rate. Zero is
// rendered as a plain "0" so a dead minute is impossible to misread.
func rate(bytes uint64, over time.Duration) string {
	if bytes == 0 {
		return "0"
	}
	bits := float64(bytes) * 8 / over.Seconds()
	switch {
	case bits >= 1e9:
		return fmt.Sprintf("%.2fGbit/s", bits/1e9)
	case bits >= 1e6:
		return fmt.Sprintf("%.1fMbit/s", bits/1e6)
	case bits >= 1e3:
		return fmt.Sprintf("%.1fkbit/s", bits/1e3)
	}
	return fmt.Sprintf("%.0fbit/s", bits)
}

// logConnected emits the single, clear "connected" line when the first link of
// the tunnel comes up (called on the 0->1 live-link transition).
func (e *Engine) logConnected(id int) {
	local := ipOnly(e.cfg.TunIP)
	peer := e.cfg.PeerTunIP
	if peer == "" {
		peer = "peer"
	}
	if e.cfg.IsSPF() {
		e.log.Info("SPF tunnel connected: %s <-> %s", local, peer)
		return
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
// It lives for the whole run and hands each packet to the scheduler in the
// pooled buffer it was read into — no per-packet allocation and no copy.
// Admission control, classification and drops are the scheduler's job.
// buildTxQueues returns one scheduler per TUN queue, or — when striping — the
// same scheduler for all of them, sized to the depth the separate ones would
// have had between them.
func (e *Engine) buildTxQueues() []*txQueue {
	qs := make([]*txQueue, e.queues)
	aqmOn := e.cfg.AQM != config.AQMOff
	if e.stripe {
		shared := newTxQueueAQM(e.channelSize*e.queues, e.cfg.MTU, e.pool, &e.qstats, aqmOn)
		for i := range qs {
			qs[i] = shared
		}
		return qs
	}
	for i := range qs {
		qs[i] = newTxQueueAQM(e.channelSize, e.cfg.MTU, e.pool, &e.qstats, aqmOn)
	}
	return qs
}

func (e *Engine) queueReader(ctx context.Context, q queue, tq *txQueue) {
	for {
		p := e.pool.get()
		n, err := q.Read(p.b[:e.pktLen])
		if err != nil {
			e.pool.put(p)
			return // device closed
		}
		if n <= 0 {
			e.pool.put(p)
			continue
		}
		p.n = n
		tq.push(p)
		if ctx.Err() != nil {
			return
		}
	}
}

// engineLabel is "SPF" or "TUN" for logs (SPF is the TUN data plane + spoofing).
func (e *Engine) engineLabel() string {
	if e.cfg.IsSPF() {
		return "SPF"
	}
	return "TUN"
}

// clientQueue keeps a link dialed for its queue and pumps, reconnecting on loss
// with exponential backoff. It counts consecutive failed attempts for the log so
// a persistent problem is visible without spamming a line per packet.
func (e *Engine) clientQueue(ctx context.Context, q queue, tq *txQueue, id int) {
	backoff := 250 * time.Millisecond
	attempt := 0
	for ctx.Err() == nil {
		lk, err := e.ldialer.DialLink(ctx)
		if err != nil {
			attempt++
			e.log.Warn("%s queue %d: reconnect attempt %d failed: %v (retrying in %s)",
				e.engineLabel(), id, attempt, err, backoff.Round(time.Millisecond))
			if !sleepCtx(ctx, &backoff) {
				return
			}
			continue
		}
		if attempt > 0 {
			e.log.Info("%s queue %d: reconnected after %d attempt(s)", e.engineLabel(), id, attempt)
		}
		attempt = 0
		backoff = 250 * time.Millisecond
		e.pump(ctx, q, tq, lk, id)
		atomic.AddUint64(&e.stats.reconnects, 1)
	}
}

// serverAccept assigns each inbound link to a free queue slot and pumps it.
func (e *Engine) serverAccept(ctx context.Context, dev *tun.Device, txQueues []*txQueue) {
	free := make(chan int, e.queues)
	for i := 0; i < e.queues; i++ {
		free <- i
	}
	var wg sync.WaitGroup
	var lastMismatchWarn atomic.Int64
	for ctx.Err() == nil {
		lk, err := e.llistener.AcceptLink()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			e.log.Warn("accept (%s): %v", config.TunModeName(e.mode), err)
			continue
		}
		var slot int
		select {
		case slot = <-free:
		default:
			// No free queue slot: the peer opened more links than this host has
			// queues — a pool/tun_queues MISMATCH. The excess link is dropped and
			// its flows would blackhole. Warn (rate-limited: the dialer hot-
			// reconnects, so this fires continuously otherwise).
			_ = lk.Close()
			if now := e.nowSec(); now-lastMismatchWarn.Load() >= 30 {
				lastMismatchWarn.Store(now)
				e.log.Error("%s: peer opened more links than pool=%d queues here — set the SAME pool/tun_queues on BOTH servers or flows will be dropped",
					e.engineLabel(), e.queues)
			}
			continue
		}
		wg.Add(1)
		go func(slot int, lk link) {
			defer wg.Done()
			defer func() { free <- slot }()
			e.pump(ctx, dev.Queues()[slot], txQueues[slot], lk, slot)
		}(slot, lk)
	}
	wg.Wait()
}

// pumpState is the state one link's reader and writer share: liveness, the
// measured RTT and the control messages the reader needs the writer to send
// (the writer owns the link's send side exclusively, so the reader may never
// write to it directly).
type pumpState struct {
	lastRecv atomic.Int64 // UnixNano of the last frame received
	ctlOut   chan ctlMsg
}

type ctlMsg struct {
	op byte
	ts uint64
}

// enqueueCtl hands a control message to the writer, dropping it if the writer
// is already backed up — a lost pong just means one skipped RTT sample.
func (p *pumpState) enqueueCtl(op byte, ts uint64) {
	select {
	case p.ctlOut <- ctlMsg{op: op, ts: ts}:
	default:
	}
}

// pump bridges one TUN queue with one link until either side fails or the
// heartbeat times out.
func (e *Engine) pump(ctx context.Context, q queue, tq *txQueue, lk link, id int) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer lk.Close()

	// On cancellation (heartbeat timeout or shutdown) close the link at once so a
	// writer blocked in WriteFrame on a dead socket unblocks immediately, rather
	// than waiting out TCP_USER_TIMEOUT — the difference between a ~1 s and a
	// ~20 s reconnect after a network drop.
	stopClose := context.AfterFunc(ctx, func() { _ = lk.Close() })
	defer stopClose()

	ps := &pumpState{ctlOut: make(chan ctlMsg, 8)}
	ps.lastRecv.Store(time.Now().UnixNano())
	if atomic.AddInt64(&e.stats.liveLinks, 1) == 1 {
		e.logConnected(id)
	}
	defer func() {
		if atomic.AddInt64(&e.stats.liveLinks, -1) == 0 && ctx.Err() == nil {
			e.log.Warn("TUN tunnel disconnected — all links down, reconnecting…")
		}
	}()
	// Whatever is still queued when the link dies is already stale by the time a
	// replacement is up; delivering it would only produce a latency spike and a
	// burst of out-of-window retransmits.
	defer tq.drain()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); defer cancel(); e.tunToLink(ctx, tq, lk, ps) }()
	go func() { defer wg.Done(); defer cancel(); e.linkToTun(ctx, q, lk, ps) }()
	e.livenessMonitor(ctx, cancel, ps, id) // blocks until ctx is done
	wg.Wait()
}

// tunToLink drains the scheduler into the link, packing as many packets as fit
// into each frame.
//
// Batching is opportunistic: packets keep accumulating while the scheduler has
// more to give, and the batch is flushed the instant it runs dry. That gives
// full-size frames exactly when the tunnel is busy enough to need them, and
// adds zero latency when it is not — unlike a fixed flush timer, which taxes
// every packet on an idle tunnel with its full period.
//
// How much may accumulate is governed by frameBudget rather than the carrier's
// hard maximum: a frame is indivisible on the wire, so its size is a floor on
// how long an express packet can be stuck behind bulk traffic (see budget.go).
func (e *Engine) tunToLink(ctx context.Context, tq *txQueue, lk link, ps *pumpState) {
	maxFrame := lk.MaxFrame()
	batch := make([]byte, 0, maxFrame)
	pending := 0
	budget := netq.New(maxFrame)

	hb := time.NewTicker(e.hbInterval)
	defer hb.Stop()

	send := func() bool {
		if len(batch) == 0 {
			return true
		}
		n := len(batch)
		start := time.Now()
		if err := lk.WriteFrame(batch); err != nil {
			return false
		}
		atomic.AddUint64(&e.stats.txPackets, uint64(pending))
		atomic.AddUint64(&e.stats.txBytes, uint64(n))
		// How long the write blocked is the tunnel's only direct measurement of
		// what the carrier can actually absorb.
		budget.Add(n, time.Since(start))
		batch = batch[:0]
		pending = 0
		return true
	}

	// room reports whether another payload of n bytes still fits this frame. A
	// packet that would not fit the budget but does fit the carrier's frame is
	// still allowed through on an empty batch, so the budget can never wedge a
	// packet (see the oversize guard below for the genuinely-too-big case).
	room := func(n int) bool {
		limit := budget.Size()
		if len(batch) == 0 && limit < n+2 {
			limit = maxFrame
		}
		return len(batch)+2+n <= limit
	}

	for {
		if ctx.Err() != nil {
			return
		}
		// Control messages ride along with whatever is already batched, so an RTT
		// probe is never delayed behind a queue drain. Checking the heartbeat here
		// as well as in the idle select below matters: a saturated tunnel never
		// reaches the idle select, and probes must keep flowing precisely when the
		// tunnel is busy enough for its latency to be worth measuring.
		select {
		case c := <-ps.ctlOut:
			if !room(ctlLen) && !send() {
				return
			}
			batch = appendControl(batch, c.op, c.ts)
		case <-hb.C:
			if !room(ctlLen) && !send() {
				return
			}
			batch = appendControl(batch, ctlPing, uint64(time.Now().UnixNano()))
		default:
		}

		p := tq.pop()
		if p == nil {
			// Queue drained: flush now rather than holding bytes back.
			if !send() {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-tq.signal():
			case c := <-ps.ctlOut:
				batch = appendControl(batch, c.op, c.ts)
				if !send() {
					return
				}
			case <-hb.C:
				batch = appendControl(batch, ctlPing, uint64(time.Now().UnixNano()))
				if !send() {
					return
				}
			}
			continue
		}

		if p.n+2 > maxFrame {
			// Larger than an empty frame can hold — only reachable if the MTU is
			// configured above what the carrier can wrap. Shed it rather than
			// letting WriteFrame fail and cycle an otherwise healthy link.
			e.qstats.dropped.Add(1)
			e.pool.put(p)
			continue
		}
		if !room(p.n) && !send() {
			e.pool.put(p)
			return
		}
		batch = appendPacket(batch, p.bytes())
		pending++
		e.pool.put(p)

		if pending >= e.batchSize || !room(e.pktLen) {
			if !send() {
				return
			}
		}
	}
}

// linkToTun reads frames, splits each into its packets, and writes them to the
// TUN queue.
func (e *Engine) linkToTun(ctx context.Context, q queue, lk link, ps *pumpState) {
	stop := context.AfterFunc(ctx, func() { _ = lk.SetReadDeadline(time.Now()) })
	defer stop()

	tunErrs := 0
	for {
		frame, err := lk.ReadFrame()
		if err != nil {
			return
		}
		ps.lastRecv.Store(time.Now().UnixNano())
		// A frame is a sequence of [uint16 len][payload] records; see datagram.go
		// for how the length discriminates heartbeats, control messages and
		// packets.
		for len(frame) >= 2 {
			plen := int(frame[0])<<8 | int(frame[1])
			frame = frame[2:]
			if plen == 0 {
				continue // legacy heartbeat: liveness already refreshed above
			}
			if plen > len(frame) {
				break // truncated frame; drop remainder
			}
			payload := frame[:plen]
			frame = frame[plen:]
			if plen < minIPPacket {
				e.handleControl(payload, ps)
				continue
			}
			if _, err := q.Write(payload); err != nil {
				// A device write failing says nothing about the carrier. The
				// kernel's queue can be momentarily full (ENOBUFS), or the peer
				// can send one packet this device will not accept (EINVAL).
				// Returning here tore the carrier down and re-dialed it —
				// hundreds of milliseconds in which everything was lost, which
				// on a datagram carrier shows up as a ping through the tunnel
				// timing out for no reason anyone can see.
				//
				// One rejected packet is one packet. Only a device that keeps
				// refusing is a real failure, and that is what the counter is
				// for; it resets on the first success so a burst of ENOBUFS
				// under load never accumulates into a teardown.
				atomic.AddUint64(&e.stats.tunWriteErrs, 1)
				tunErrs++
				if tunErrs > maxTunWriteErrs {
					e.log.Error("TUN device refused %d packets in a row (%v) — cycling the link",
						tunErrs, err)
					return
				}
				continue
			}
			tunErrs = 0
			atomic.AddUint64(&e.stats.rxPackets, 1)
			atomic.AddUint64(&e.stats.rxBytes, uint64(plen))
		}
	}
}

// handleControl answers a peer's RTT probe and records our own round trip.
func (e *Engine) handleControl(payload []byte, ps *pumpState) {
	op, ts, ok := parseControl(payload)
	if !ok {
		atomic.AddUint64(&e.stats.badFrames, 1)
		return
	}
	switch op {
	case ctlPing:
		ps.enqueueCtl(ctlPong, ts)
	case ctlPong:
		rtt := time.Now().UnixNano() - int64(ts)
		if rtt <= 0 || rtt > int64(time.Minute) {
			return // clock stepped or an absurdly stale echo
		}
		e.recordRTT(rtt)
	}
}

// recordRTT folds a sample into an exponentially weighted moving average (1/8
// weight, the same smoothing TCP uses for its SRTT).
func (e *Engine) recordRTT(sample int64) {
	for {
		old := atomic.LoadInt64(&e.stats.rttNs)
		next := sample
		if old > 0 {
			next = old + (sample-old)/8
		}
		if atomic.CompareAndSwapInt64(&e.stats.rttNs, old, next) {
			return
		}
	}
}

// livenessMonitor cancels the pump if no frame arrives within hbTimeout. It
// polls at a fraction of the timeout so detection is prompt without depending
// on the heartbeat period.
func (e *Engine) livenessMonitor(ctx context.Context, cancel context.CancelFunc, ps *pumpState, id int) {
	tick := e.hbTimeout / 4
	if tick < 250*time.Millisecond {
		tick = 250 * time.Millisecond
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			age := time.Duration(time.Now().UnixNano() - ps.lastRecv.Load())
			if age > e.hbTimeout {
				e.log.Warn("%s connection lost on queue %d: no traffic for %s (limit %s) — cycling link",
					e.engineLabel(), id, age.Round(time.Millisecond), e.hbTimeout)
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
	// RTTMs is the smoothed round trip of the tunnel links themselves, measured
	// with control frames. Compare it against a ping through the tunnel: a large
	// gap means queueing, not path latency.
	RTTMs float64 `json:"rtt_ms"`
	// ExpressPackets / BulkPackets show how traffic splits across the two
	// service classes; TxDropped counts AQM and overflow drops, which are the
	// congestion signal that keeps queueing delay bounded (a small, steady
	// number under load is healthy, not a fault).
	ExpressPackets uint64 `json:"express_packets"`
	BulkPackets    uint64 `json:"bulk_packets"`
	TxDropped      uint64 `json:"tx_dropped"`
	// The three reasons a transmit-queue drop happens, apart. AQM dropping is
	// the system signalling congestion and is healthy; a full ring is the system
	// out of room; a stale express packet was overtaken by a fresher one.
	AQMDropped   uint64 `json:"aqm_dropped"`
	QueueFull    uint64 `json:"queue_full_dropped"`
	StaleDropped uint64 `json:"stale_dropped"`
	QueueDepth   int64  `json:"queue_depth"`
	BadFrames    uint64 `json:"bad_frames"`
	// The three things bad_frames used to be, kept apart because they have
	// nothing in common but the symptom. See authFailed and notOurs in link.go.
	AuthFailed uint64 `json:"auth_failed"`
	BadControl uint64 `json:"bad_control"`
	NotOurs    uint64 `json:"not_ours"`

	// What follows is here because "the tunnel is unstable" is unanswerable
	// without it. Each of these is a distinct cause with a distinct fix, and
	// each used to be invisible.
	//
	// TunWriteErrors: packets the local TUN device refused. A few under load is
	// an overfull device queue; a steady stream is a device or MTU problem, not
	// the path.
	TunWriteErrors uint64 `json:"tun_write_errors"`
	// CarrierDropped: datagrams the carrier's demultiplexer could not hand to a
	// link because that link was not draining fast enough. This is local
	// backpressure, not path loss.
	CarrierDropped uint64 `json:"carrier_dropped"`
	// CarrierWriteErrors: frames the carrier socket refused to send (a full
	// interface queue, a firewall rate-limiter). Lost locally, not on the path.
	CarrierWriteErrors uint64 `json:"carrier_write_errors"`
	// DupSent / DupDropped: small frames sent twice, and copies the replay
	// window discarded. DupDropped rising towards DupSent means the path is
	// clean and the second copy is pure insurance; a large gap means the path
	// is losing frames and the duplication is doing its job.
	DupSent    uint64 `json:"dup_sent"`
	DupDropped uint64 `json:"dup_dropped"`
}

// Healthy reports whether at least one link of the tunnel is currently up. The
// core watchdog uses it to detect a wedged tunnel and force a clean restart.
func (e *Engine) Healthy() bool { return atomic.LoadInt64(&e.stats.liveLinks) > 0 }

// Snapshot returns current counters (as any, to satisfy the shared engine
// interface used by the health endpoint).
func (e *Engine) Snapshot() any {
	return Stats{
		LiveLinks:          atomic.LoadInt64(&e.stats.liveLinks),
		TxPackets:          atomic.LoadUint64(&e.stats.txPackets),
		RxPackets:          atomic.LoadUint64(&e.stats.rxPackets),
		TxBytes:            atomic.LoadUint64(&e.stats.txBytes),
		RxBytes:            atomic.LoadUint64(&e.stats.rxBytes),
		Reconnects:         atomic.LoadUint64(&e.stats.reconnects),
		RTTMs:              float64(atomic.LoadInt64(&e.stats.rttNs)) / float64(time.Millisecond),
		ExpressPackets:     e.qstats.expressPkts.Load(),
		BulkPackets:        e.qstats.bulkPkts.Load(),
		TxDropped:          e.qstats.dropped.Load(),
		QueueDepth:         e.qstats.depth.Load(),
		BadFrames:          atomic.LoadUint64(&e.stats.badFrames) + badDatagrams.Load(),
		AuthFailed:         authFailed.Load(),
		BadControl:         atomic.LoadUint64(&e.stats.badFrames),
		NotOurs:            notOurs.Load(),
		TunWriteErrors:     atomic.LoadUint64(&e.stats.tunWriteErrs),
		CarrierDropped:     carrierDropped.Load(),
		CarrierWriteErrors: carrierWriteErrs.Load(),
		DupSent:            dupSent.Load(),
		DupDropped:         dupDropped.Load(),
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

// datagramCarrier reports whether the config uses a datagram-based L3 carrier
// (any SPF profile, or a TUN mode other than the reliable tcp stream).
func datagramCarrier(cfg *config.Config) bool {
	if cfg.IsSPF() {
		return true
	}
	return cfg.TunMode != "" && cfg.TunMode != config.TunModeTCP
}

// Liveness defaults. Probes are cheap — they ride inside whatever frame is
// already being written — so they are frequent enough to cycle a dead link in
// well under the old 25 s, which is the difference between a blip and a
// noticeable outage on a flaky intercontinental path.
// The values themselves live in package config, shared with the mux engine, so
// the two cannot drift apart: see config.DefaultHeartbeatSec.

// channelDefault sizes the per-queue TX ring by profile. The ring only has to
// absorb bursts: CoDel keeps the *occupied* depth near 5 ms of drain time
// whatever the capacity is, so a deeper ring costs memory, not latency.
// channelDefault sizes the transmit ring — how much of a burst the tunnel can
// absorb before it starts dropping at the tail.
//
// This used to be 512 packets, about 676 KB at the datagram carriers' MTU. On a
// long path that is too small to be a burst absorber: Iran to Europe runs
// 100-150 ms, so a 100 Mbit path has one to two megabytes in flight, and inner
// TCP fills that. A burst arriving faster than CoDel's interval overflowed the
// ring and was tail-dropped — the crude drop that CoDel exists to replace, and
// one that costs throughput rather than signalling congestion gently.
//
// The ring is now deep enough to hold a real burst. That is only safe because
// there is an AQM in front of it: CoDel bounds how long a packet may *sit* in
// the queue, whatever the queue's capacity, so extra capacity buys burst
// absorption without buying standing delay. Without an AQM, a ring this size
// would be a second of bufferbloat. The ring itself costs eight bytes an entry;
// packet buffers are pooled and only exist while occupied, so the memory
// follows actual load rather than capacity.
func channelDefault(profile string) int {
	switch profile {
	case config.ProfileFast:
		return 4096
	case config.ProfileResource:
		return 256 // a small VPS: cap what a sustained backlog can hold
	default: // balance
		return 2048
	}
}

// maxDialBackoff caps the reconnect backoff. Failover matters more than saving
// a dial, so the ceiling is low and the first retries are sub-second.
const maxDialBackoff = 5 * time.Second

func sleepCtx(ctx context.Context, b *time.Duration) bool {
	t := time.NewTimer(*b)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		if *b < maxDialBackoff {
			if *b *= 2; *b > maxDialBackoff {
				*b = maxDialBackoff
			}
		}
		return true
	}
}
