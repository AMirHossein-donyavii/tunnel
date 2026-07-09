# Changelog

All notable changes to Emergency Tunnel are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/), and the
project uses [Semantic Versioning](https://semver.org/).

## [1.6.0] — 2026-07-09

Adds the SPF protocol, fixes the update-then-reload flow, and applies a measured
performance pass.

### Fixed
- **Update now reloads automatically.** Panel option 8 downloads + verifies the
  new version, and on success **re-execs `et`** so you're immediately on the new
  build (no manual restart). On failure it keeps the previous version and says so.

### Added
- **SPF protocol (`spf`) — beta.** TUN + IPX-style encapsulation with **source-IP
  spoofing** over ICMP (raw sockets) or a reliable TCP profile. A point-to-point
  obfuscation tunnel between two servers you control: outgoing packets use
  `spoof_src_ip`; inbound are accepted only from `spoof_dst_ip` (reversed on the
  two sides). New config: `spf_profile`, `encapsulation`, `spoof_src_ip`,
  `spoof_dst_ip`. Panel offers it as protocol #3. Reuses the datagram AEAD, link,
  batching, heartbeat, and reconnect from the TUN carriers. Linux + `CAP_NET_RAW`;
  compiled + cross-built + framing/validation tested, **not runtime-verified in
  CI** — validate on a Linux host. `configs/example-spf.toml` added.

### Performance (reviewed against the reference tuning config)
- **Applied:** `batch_size` default 32→**64** (fills the ~60 KiB TCP frame →
  fewer frames/syscalls); `channel_size` default 512→**1024** (better burst
  absorption at modest RAM). Latency still bounded by the 2 ms flush.
- **Rejected:** `kdf_iterations=100000` — we derive keys from ECDH + HKDF, not a
  password, so PBKDF-style iterations would burn CPU per handshake for **zero**
  benefit. `algorithm="aes-256-gcm"` not forced — ChaCha20 wins without AES-NI
  and both ends must match, so the default stays `chacha20-poly1305` (panel still
  offers AES). `so_sndbuf=0` not adopted — our profile-based buffers beat the OS
  default on high-BDP links. `workers=0`/`auto_tuning` already present.

### Verified
- linux amd64/arm64/armv7 build (incl. SPF); `go vet` clean; tests green incl.
  `-race`; mux tunnel loopback still forwards; SPF (both profiles) + spoof
  validation pass; bad/missing spoof rejected.

## [1.5.0] — 2026-07-09

Adds selectable **TUN carrier modes** and removes the Direct direction.

### Added
- **TUN modes (`tun_mode`)** — choose how the encrypted link between the two
  servers is carried:
  - **`tcp`** (default, production) — reliable stream (existing).
  - **`udp`** (production) — UDP datagrams with a new **datagram AEAD**
    (explicit per-packet nonce, loss/reorder tolerant) and a retransmitted
    X25519 handshake. Verified end-to-end over loopback (both ciphers, `-race`).
  - **`icmp`** / **`bip`** (ICMPv6) — **beta** — frames ride in ICMP echo
    payloads (ping mimicry) over raw sockets; Linux + `CAP_NET_RAW`. Requires
    `net.ipv4.icmp_echo_ignore_all=1` on the listener. Compiled & cross-built;
    **validate on a Linux host** (raw sockets are not runtime-testable in CI here).
  - The wizard now shows the mode menu immediately after selecting TUN, with a
    clear explanation of TCP mode.
- **`link` abstraction** in the TUN engine (`WriteFrame`/`ReadFrame`) so all four
  carriers share the same batching, heartbeat, and reconnect logic.
- `crypto.Datagram` (connectionless AEAD) + `ClientHandshakePacket`/
  `ServerHandshakePacket`.

### Removed
- **Direct mode — completely.** `mode` is reverse-only (Foreign dials Iran);
  `ModeDirect` and the panel Direction question are gone. Validation rejects
  `mode = "direct"`.

### Kept (reviewed)
- **Health/stats port** — kept and confirmed **local-only** (`127.0.0.1`), used
  by the panel status view and debugging; validation prevents collision with
  `tunnel_port`; set `health_port = 0` to disable.

### Changed
- New dependency `golang.org/x/net` (ICMP marshaling/checksums).
- Panel input handling continues to re-prompt on invalid values (ports, IPs,
  names, menu choices) and never aborts.

### Verified
- linux amd64/arm64/armv7 build (incl. ICMP); `go vet` clean; tests green incl.
  `-race`; UDP carrier loopback e2e; TUN configs for all four modes validate;
  Direct/invalid-mode rejected.

## [1.4.0] — 2026-07-09

Streamlines the project to **two tunnel protocols** and makes **TUN** a
first-class, production-quality protocol.

### Removed
- **The `l4` (simple TCP forwarder) engine — completely.** Package
  `internal/forward`, the `EngineL4` value, its core wiring, panel option, and
  docs are gone. Re-create any old `l4` tunnels as `mux` (same `forwards`).

### Changed
- **Protocol list is now exactly two:** **1) TCP Reverse Tunnel (`mux`)** and
  **2) TUN (`tun`)**. TCP Reverse remains the default/primary.
- **TUN promoted to first-class** (engine value `tun`; the old `l3` value is
  accepted as a deprecated alias and normalised on load). Defaults: Iran
  `10.10.10.1`, Foreign `10.10.10.2` on `10.10.10.0/24`. Carries all IP traffic
  (TCP/UDP/ICMP/IPv6-ICMP). Optional `tun_ip6` for an IPv6 tunnel address.

### Added
- **TUN validation** using `net.ParseCIDR`: `tun_ip` must be a valid IPv4 CIDR;
  `peer_tun_ip` must be a valid IP inside the same subnet and differ from
  `tun_ip`; `tun_ip6` (if set) must be a valid IPv6 CIDR.
- **Connection logging:** a clear "Tunnel connected successfully:
  Iran <ip> <-> Foreign <ip>" line on the first live link, plus disconnect/
  reconnect events — all per-link (no per-packet log spam).
- **Robust wizard input:** every field (ports, IPs, name, protocol, numbers)
  now **re-prompts until valid** and never aborts on empty/invalid input.
  New helpers: `ask_port`, `ask_ipcidr`, `ask_int`, `ask_name`, `ask_oneof`,
  `ask_choice`, `ask_req`. Duplicate tunnel names re-prompt too.
- Panel TUN section explains the virtual-interface model and auto-fills
  `tun_ip` / `peer_tun_ip` per role.

### Verified
- linux amd64/arm64/armv7 build; `go vet` clean; tests green including `-race`;
  TUN + TCP-Reverse example configs validate; end-to-end mux loopback forwards
  data; TUN subnet/peer validation rejects bad configs.

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
