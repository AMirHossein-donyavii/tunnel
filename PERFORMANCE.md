# Performance & Resource Optimization Notes

Target hardware: **2 CPU cores, 2–4 GB RAM**. The core is designed to run several
tunnels concurrently without noticeable CPU or memory pressure.

## Where the packets queue (read this first)

Almost every "the tunnel is slow / the ping spikes" symptom is a queueing
problem, not a bandwidth one. There are four places a backlog can build between
the two servers, and the tunnel now manages all four:

| Queue | Managed by | Why it matters |
|-------|-----------|----------------|
| TUN device egress | `fq_codel` + short `txqueuelen` | per-flow fairness: a download cannot delay an interactive session |
| Engine TX queue | express class + CoDel AQM (`internal/l3/sched.go`) | keeps queueing delay near 5 ms instead of hundreds of ms |
| Kernel socket send queue | `TCP_NOTSENT_LOWAT` = 128 KiB | anything here is beyond the scheduler's reach; capping it keeps the queue where priority still applies |
| Kernel socket send buffer size | left to `tcp_wmem` autotuning | pinning a large `SO_SNDBUF` turns it into a multi-megabyte standing FIFO |
| The frame itself | adaptive frame budget (`internal/l3/budget.go`) | a frame is indivisible on the wire, so its size is a hard floor on how long an express packet can be blocked |

A ping that sits at ~100 ms and jumps to 400 ms the moment a transfer starts is
the classic signature of an unmanaged queue: the ICMP packet is sitting behind a
few hundred kilobytes of bulk data. The express class removes exactly that wait,
and CoDel stops the backlog forming in the first place.

**Reading `/stats`:** `rtt_ms` is the tunnel link's own round trip, measured with
control frames. Compare it against a ping *through* the tunnel — if the ping is
much higher, the extra time is queueing, not the path. `tx_dropped` rising
steadily under load is CoDel doing its job (it is the congestion signal inner TCP
needs), not packet loss to worry about; `bad_frames` rising means corrupt,
forged or replayed carrier packets.

## Memory

- **Pooled splice buffers.** All data copying uses a `sync.Pool` of 32 KiB
  buffers (`internal/muxeng`), so steady-state forwarding allocates ~nothing on
  the hot path and keeps GC pressure low.
- **Bounded frame buffers.** AEAD framing caps plaintext at 16 KiB; each
  `SecureConn` keeps a single reusable read buffer and a single write scratch
  buffer instead of allocating per frame. Nonces are stamped into fixed 12-byte
  arrays (no per-frame allocation).
- **Soft heap limit.** On the `balance`/`resource` profiles the core reads the
  cgroup memory limit and calls `debug.SetMemoryLimit(0.85–0.90 × limit)`, so the
  Go runtime reclaims aggressively before the container OOMs. The systemd unit
  adds `MemoryMax=256M` as a hard backstop.
- **No unbounded fan-out.** Inbound handshakes are capped by a semaphore
  (`handshakeSlot = 128`); excess links are shed rather than buffered.

## CPU

- **cgroup-aware sizing.** `GOMAXPROCS` is set to the *effective* CPU count,
  which honours cgroup v2 `cpu.max` and v1 `cpu.cfs_quota_us/period` — a 1-vCPU
  slice of an 8-core host uses 1, not 8. Manual `workers` overrides this.
- **Exact worker pool.** On the dialing side exactly `pool` goroutines each own
  one warm link for its lifetime; when a link is consumed the same goroutine
  redials. No busy-loops, no timer churn, no over-dialing.
- **`TCP_NODELAY`** on both the tunnel links and the local exit dials to avoid
  Nagle-induced latency for interactive/proxy traffic.
- **One syscall per frame.** The AEAD layer seals the length prefix and the
  ciphertext into a single buffer and issues one `write`. Frames carry up to
  63 KiB, so a full 60 KiB packet batch is one frame, one seal, one syscall
  (previously four frames and eight writes, one of which was a 2-byte segment).
- **Adaptive frame budget.** How much is packed into a frame is chosen from the
  link's measured drain rate, not a fixed byte count, so one frame never occupies
  the wire for more than ~4 ms. 60 KiB is right on a gigabit link (0.5 ms) and
  badly wrong on a 20 Mbit one (24 ms — enough head-of-line blocking to negate
  the priority scheduler entirely). The rate is measured from how long writes
  actually *block*, which is the only signal that distinguishes a slow link from
  an idle one; a link that never blocks keeps the full 60 KiB frame.
- **Zero-allocation hot path.** Packets are read straight into pooled buffers
  and recycled after framing; the datagram carriers pool their demultiplexer
  buffers too. `BenchmarkQueuePushPop` and `BenchmarkWriteFrame` both report
  0 allocs/op.
- **GC tuning by profile.** `fast` uses `GOGC=200` (fewer collections, a little
  more RAM); `resource` uses `GOGC=50` (tighter memory, slightly more CPU);
  `balance` uses the default 100.

## Network

- **Warm connection pool** eliminates per-request TCP+handshake latency: user
  connections grab an already-authenticated link.
- **Single-frame control channel.** The OPEN frame (remote port + optional PROXY
  header) is one AEAD frame; subsequent bytes are spliced raw, so the per-stream
  overhead is one small frame plus the tag/length per 16 KiB chunk.
- **Backpressure, not drops.** If every pooled link is busy, a new user waits up
  to `assignTO` (4 s) for a worker rather than being dropped instantly; if links
  are genuinely down it fails fast with a logged error.

## Profiles

| Profile    | GOGC | Heap soft-limit | Best for                         |
|------------|------|-----------------|----------------------------------|
| `fast`     | 200  | off             | throughput on roomy servers      |
| `balance`  | 100  | 0.90 × cgroup   | the sensible default             |
| `resource` | 50   | 0.85 × cgroup   | tiny/oversold VPS, many tunnels  |

## L3 TUN engine tuning

The L3 engine (`engine = "l3"`) has its own knobs:

- **`pool`** sets the number of TUN queues *and* encrypted links. The kernel
  hashes each flow to a fixed queue, so ordering is preserved while flows spread
  across cores. Keep `pool ≈ CPU cores` — more queues than cores just share
  cores (the core logs a warning if you overshoot).
- **`batch_size`** (default 64) — packets coalesced into one frame. Higher values
  raise throughput for bulk transfers and lower syscall/CPU cost. There is no
  flush timer to tune: the batch is flushed as soon as the queue drains, so this
  only ever caps how large a batch may get, never how long one is held.
- **`channel_size`** (default 256, profile-dependent) — per-queue ring capacity.
  This is a *burst absorber*, not a standing queue: CoDel keeps the occupied
  depth near 5 ms of drain time whatever the capacity is, so a deeper ring costs
  memory, not latency. Raise it for very bursty traffic; lower it to cap memory
  on a tiny VPS.
- **`so_sndbuf` / `so_rcvbuf`** — socket buffers. Left at 0 they follow the
  profile (fast = 4 MiB, balance = 1 MiB, resource = 256 KiB). For high
  bandwidth-delay-product links (intercontinental), larger buffers help.
- **BBR** is requested on every link automatically; enable it kernel-wide for
  best effect: `net.core.default_qdisc=fq`, `net.ipv4.tcp_congestion_control=bbr`.
- **`heartbeat_interval` / `heartbeat_timeout`** (default 3 s / 12 s) — probes
  ride inside frames that are being written anyway, so they are close to free;
  the defaults cycle a dead link in ~12 s. Lower them for even faster failover on
  flaky links, raise them on stable links to reduce wakeups. They also drive the
  `rtt_ms` measurement, so very long intervals mean stale RTT data.
- **MTU**: 1380 is a safe default that survives most encapsulation overhead. If
  the underlay drops fragments, lowering to ~1280 avoids black-holing.

The L3 hot path reuses read buffers via a `sync.Pool` and coalesces packets into
≤16 KiB AEAD frames, so steady-state RAM stays flat and GC pressure is low even
at high packet rates.

## Host sysctls

The core inspects these at startup and logs a specific, actionable warning for
any that are working against it — check the log before tuning by hand:

```
net.ipv4.tcp_congestion_control = bbr        # recovers from loss/reordering on long paths
net.core.default_qdisc           = fq        # paces BBR, keeps the NIC queue short
net.ipv4.tcp_rmem                = 4096 131072 16777216
net.ipv4.tcp_wmem                = 4096 65536 16777216
net.ipv4.tcp_slow_start_after_idle = 0       # stops idle links restarting from a tiny window
```

The `tcp_rmem`/`tcp_wmem` ceilings matter more than they look on an
Iran↔Europe path: at ~100 ms RTT, 100 Mbit needs ~1.2 MB in flight, so a small
ceiling caps single-link throughput no matter what the tunnel does.
`tcp_slow_start_after_idle=1` is the reason a tunnel that has been quiet for a
minute feels sluggish for the first second of the next transfer.

## Tuning checklist for busy nodes

1. Raise file descriptors — the unit already sets `LimitNOFILE=1048576`.
2. Increase `pool` (e.g. 16–32) only if you see "no tunnel link available" under
   bursty load; each pooled link is cheap but not free.
3. Consider kernel niceties on the exit host:
   `net.core.somaxconn`, `net.ipv4.tcp_fastopen`, BBR
   (`net.core.default_qdisc=fq`, `net.ipv4.tcp_congestion_control=bbr`).
4. Watch `curl -s http://127.0.0.1:<health_port>/stats` for `link_errors` — a
   rising count means handshake or connectivity problems, not data errors.
