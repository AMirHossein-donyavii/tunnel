# Changelog

All notable changes to Emergency Tunnel are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/), and the
project uses [Semantic Versioning](https://semver.org/).

## [1.2.0] — 2026-07-08

Next-generation **multiplexed TCP reverse tunnel** (`engine = "mux"`) — a
clean-room stream multiplexer that targets lowest latency and highest stability
for reverse-proxy workloads, plus a full TCP tuning pass. Inspired by the
pengutunnel/Backhaul approaches, redesigned rather than copied.

### Added
- **`mux` engine** — many user connections carried as lightweight streams over a
  small pool of long-lived, authenticated links:
  - **Custom binary framing** (10-byte header; `DATA/SYN/WINDOW_UPDATE/FIN/RST/
    PING/GOAWAY`).
  - **Per-stream flow control** (256 KiB windows) → one heavy/slow stream can't
    stall others; bounded memory.
  - **Two-class priority write scheduler with adaptive batching** → low latency
    under light load, few syscalls under heavy load.
  - **PING-based heartbeat + RTT measurement** with automatic session recovery.
  - New connection = one SYN frame (no extra TCP/crypto handshake): measured
    **2.3× lower setup latency on a 20 ms link** and **8× fewer allocations**
    than a per-connection handshake (`internal/muxeng` benchmarks).
- **Full TCP tuning** (`internal/nettune`): `TCP_QUICKACK`, `TCP_USER_TIMEOUT`,
  keepalive idle/interval/count, alongside the existing `TCP_NODELAY`,
  `SO_SNDBUF/RCVBUF`, and BBR.
- **Benchmarks** comparing mux vs per-connection handshake (setup latency,
  allocations) and single-stream throughput (~1.7 GB/s in-memory).
- `-race` unit tests for the multiplexer (echo, 64 concurrent streams, 4 MiB
  flow-controlled transfer, ping RTT, close semantics).
- Example config `configs/example-mux.toml`; `docs/PROTOCOL.md` architecture doc.

### Changed
- Core version → 1.2.0. `core.Run` now selects among `mux` / `l4` / `l3`; the
  panel create-wizard offers `mux` as the recommended default.
- The `/stats` endpoint reports live sessions, stream counts, and best RTT for
  mux tunnels.

### Compatibility
- **Fully backward compatible**: `l4` and `l3` are unchanged; `mux` is opt-in.
  The handshake, PSK, and AEAD framing are unchanged, so existing keys stay valid.
- Both ends of a tunnel must use the **same** engine. To upgrade an `l4` tunnel
  to `mux`, set `engine = "mux"` on both sides and restart (you can also lower
  `pool` to 2–4 since each session carries many streams).

### Verified
- Cross-compiles for linux amd64 / arm64 / armv7; `go vet` clean; test suite
  green including `-race`.

## [1.1.0] — 2026-07-08

Major protocol upgrade: a second, higher-performance data plane inspired by the
pengutunnel and Backhaul reference architectures, plus a full compile/test gate.

### Added
- **L3 TUN engine (`engine = "l3"`)** — a full IP tunnel (WireGuard-style):
  - Creates a multi-queue TUN interface; the kernel spreads flows across queues
    (per-flow ordering preserved) for real multi-core parallelism.
  - **N encrypted links = N queues**, paired 1:1 — this replaces the old
    one-stream-per-connection pooling with a true multiplexed packet plane.
  - **Packet batching** (`batch_size`) coalesces packets into as few AEAD frames
    as possible, cutting syscalls and per-packet overhead.
  - **Application-level heartbeat** (`heartbeat_interval` / `heartbeat_timeout`)
    detects dead links; the dialer reconnects with backoff, the listener frees
    the slot — sub-30s recovery by default.
  - One persistent reader per queue → no goroutine/connection leaks across
    reconnects.
- **Socket/kernel tuning** (`internal/nettune`): per-profile `SO_SNDBUF`/
  `SO_RCVBUF`, `TCP_NODELAY`, and best-effort **BBR** congestion control, with
  `so_sndbuf` / `so_rcvbuf` overrides.
- **New config fields**: `engine`, `heartbeat_interval`, `heartbeat_timeout`,
  `batch_size`, `channel_size`, `so_sndbuf`, `so_rcvbuf`.
- **Panel**: create-wizard now selects the engine (L4 forwarder vs L3 TUN) and
  writes the appropriate config.
- **Tests**: config validation, crypto handshake + AEAD round-trip (both
  ciphers, wrong-PSK rejection), and datagram framing/batching round-trip.
- Example config `configs/example-l3.toml`.

### Changed
- Core version → 1.1.0; the health `/stats` endpoint now reports the active
  `engine` and, for L3, live link / packet / byte / reconnect counters.
- systemd unit now grants `CAP_NET_ADMIN` (needed to create/configure the TUN
  device) alongside the existing minimal capability set.
- `core.Run` selects the data plane from `engine`; both engines share one
  interface and the health endpoint.

### Compatibility
- **Backward compatible for L4**: existing configs default to `engine = "l4"`
  and behave exactly as before. L3 is opt-in per tunnel.
- The two engines do **not** interoperate with each other — both ends of a
  tunnel must use the same `engine` (and the same PSK/cipher, as before).

### Verified
- Cross-compiles for linux amd64 / arm64 / armv7; `go vet` clean; test suite
  green.

## [1.0.0] — 2026-07-07

Initial release.

### Added
- L4 TCP port-forwarding engine: pooled links, reverse + direct modes,
  AEAD encryption (ChaCha20-Poly1305 / AES-256-GCM), mutual-auth handshake with
  replay resistance, PROXY protocol v2, single/list/range/mapping forwards.
- Interactive `et` management panel, one-command signed/checksummed installer,
  per-tunnel systemd template units, structured rotating logs, health endpoint.
- Release tooling (`build-release.sh`) and hosting guide.

[1.2.0]: https://github.com/AMirHossein-donyavii/tunnel/releases/tag/v1.2.0
[1.1.0]: https://github.com/AMirHossein-donyavii/tunnel/releases/tag/v1.1.0
[1.0.0]: https://github.com/AMirHossein-donyavii/tunnel/releases/tag/v1.0.0
