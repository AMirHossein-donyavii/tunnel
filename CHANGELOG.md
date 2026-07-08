# Changelog

All notable changes to Emergency Tunnel are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/), and the
project uses [Semantic Versioning](https://semver.org/).

## [1.3.0] — 2026-07-08

Removes the pre-shared key entirely and clarifies the port model. **Breaking**
change to the link handshake — both ends must run 1.3.0.

### Removed
- **PSK (pre-shared key) — completely.** No `psk` config field, no `et-core
  genpsk`, no panel prompt, no validation, no docs. There is nothing to copy
  between servers anymore.

### Changed
- **Encryption is now key-exchange-based:** each link performs an **ephemeral
  X25519 ECDH** handshake and derives per-direction AEAD keys via HKDF. Fresh
  keys every connection (**forward secrecy**). AEAD framing (ChaCha20-Poly1305 /
  AES-256-GCM) is unchanged.
- **Port model clarified.** The server↔server port is now `tunnel_port`
  (renamed from `listen_port`; the old key is still accepted as a deprecated
  alias). It must be identical on both sides (default `1234`). The user
  VPN/data ports (`forwards`) are the "listen ports" and exist only on the Iran
  side — the Kharej side is never asked for one. Panel prompts relabelled
  accordingly.
- Config validation now rejects `health_port == tunnel_port`.

### Security note
- The ephemeral exchange provides **confidentiality + forward secrecy but not
  peer authentication** (there is no shared secret to authenticate with). This
  defeats passive DPI/censorship (the primary threat) but not an active MITM.
  **Restrict the tunnel port to the peer's IP with a firewall**, e.g.
  `ufw allow from <PEER_IP> to any port 1234 proto tcp`.

### Verified
- End-to-end loopback tunnel (Iran↔Kharej, mux engine) forwards data correctly
  with no PSK. linux amd64/arm64/armv7 build; `go vet` clean; tests green
  including `-race`; example configs validate; old `listen_port` alias parses.

## [1.2.1] — 2026-07-08

Production review: corrected defaults, clearer naming/UX, and networking
fixes/optimizations. No wire-protocol change; existing configs keep working.

### Changed (defaults)
- Default interface name `pengutun` → **`emergency-tun`** (project-based; ≤15-char
  kernel limit). Replaced everywhere (config, panel, examples, docs).
- Default TUN subnet `10.20.0.x` → **`10.10.10.1/24`** (Iran) / **`10.10.10.2/24`**
  (Kharej), same subnet both sides.
- **Tunnel port** (server↔server link) default `443` → **`1234`**.
- Health/stats port default `1234` → **`9090`** (so it can't collide with the
  tunnel port); added a validation guard rejecting `health_port == listen_port`.
- Default engine → **`mux` (TCP Reverse Tunnel)**; it is now presented as method
  **#1** in the panel, and `et-core transports` lists the production `tcp`
  transport first.

### UX
- Panel: the VPN/data-port prompt now explains "This is your VPN
  configuration/data port. Users connect through this port. Common choices are
  ports like 443," and defaults to `443`.
- Interface/subnet prompts now appear only for the L3 engine (forwarders don't
  use them), removing confusion.

### Fixed / optimized (networking)
- **mux stream leak**: fully-closed streams are now reaped from the session map
  (long-lived sessions with many short connections no longer grow unboundedly).
- **mux read path**: removed a per-frame heap allocation (reuse one read buffer;
  `deliver` copies) — less GC pressure at high packet rates.
- **mux flow-control window** 256 KiB → **512 KiB**: lifts the single-stream
  throughput cap on long-distance / high-BDP links; costs RAM only for bytes
  actually in flight.
- Full TCP tuning already applied on links (`TCP_NODELAY/QUICKACK/USER_TIMEOUT`,
  `SO_SNDBUF/RCVBUF`, keepalive, BBR).

### Verified
- linux amd64/arm64/armv7 build; `go vet` clean; tests green including `-race`
  and a new stream-reaping test.

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
