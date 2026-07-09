# Performance & Resource Optimization Notes

Target hardware: **2 CPU cores, 2–4 GB RAM**. The core is designed to run several
tunnels concurrently without noticeable CPU or memory pressure.

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
- **`batch_size`** (default 64) — packets coalesced into one write. Higher values
  raise throughput for bulk transfers and lower syscall/CPU cost; very high
  values add a little latency. The 2 ms flush timer bounds latency regardless.
- **`channel_size`** (default 1024) — per-queue buffer depth. Raise it for very
  bursty traffic; lower it to cap memory on tiny VPS.
- **`so_sndbuf` / `so_rcvbuf`** — socket buffers. Left at 0 they follow the
  profile (fast = 4 MiB, balance = 1 MiB, resource = 256 KiB). For high
  bandwidth-delay-product links (intercontinental), larger buffers help.
- **BBR** is requested on every link automatically; enable it kernel-wide for
  best effect: `net.core.default_qdisc=fq`, `net.ipv4.tcp_congestion_control=bbr`.
- **`heartbeat_interval` / `heartbeat_timeout`** — lower them for faster failover
  on flaky links (at the cost of a little more chatter), raise them on stable
  links to reduce wakeups.
- **MTU**: 1380 is a safe default that survives most encapsulation overhead. If
  the underlay drops fragments, lowering to ~1280 avoids black-holing.

The L3 hot path reuses read buffers via a `sync.Pool` and coalesces packets into
≤16 KiB AEAD frames, so steady-state RAM stays flat and GC pressure is low even
at high packet rates.

## Tuning checklist for busy nodes

1. Raise file descriptors — the unit already sets `LimitNOFILE=1048576`.
2. Increase `pool` (e.g. 16–32) only if you see "no tunnel link available" under
   bursty load; each pooled link is cheap but not free.
3. Consider kernel niceties on the exit host:
   `net.core.somaxconn`, `net.ipv4.tcp_fastopen`, BBR
   (`net.core.default_qdisc=fq`, `net.ipv4.tcp_congestion_control=bbr`).
4. Watch `curl -s http://127.0.0.1:<health_port>/stats` for `link_errors` — a
   rising count means handshake or connectivity problems, not data errors.
