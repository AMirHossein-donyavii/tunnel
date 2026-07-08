# Emergency Tunnel

A high-performance **Iran ↔ Kharej (foreign)** tunneling platform: a small static
Go core plus an interactive management panel, built for stability and very low
CPU/RAM usage on cheap VPS servers (2 cores / 2–4 GB).

> Clean-room, original implementation. It is *inspired by* the architecture and
> UX of Backhaul-style tools (Go core + bash manager, TOML configs, per-tunnel
> systemd units) but shares no code with them and contains no license-bypass or
> binary-patching logic.

---

## Highlights

- **Three data-plane engines** (choose per tunnel — see [docs/PROTOCOL.md](docs/PROTOCOL.md)):
  - **`mux`** — **multiplexed TCP reverse tunnel**: many user connections become
    lightweight **streams over a few long-lived links**. A new connection costs
    one SYN frame (no extra handshake) → **lowest latency**, scales to thousands
    of connections. Per-stream **flow control**, priority scheduling, adaptive
    batching, PING/RTT health. *(recommended)*
  - **`l4`** — simple TCP **port-forwarder**: one pooled link per connection,
    reverse **and** direct modes, PROXY protocol v2. *(simplest)*
  - **`l3`** — **TUN IP tunnel** (WireGuard-style): a multi-queue TUN device with
    **N encrypted links = N queues**, **packet batching**, **heartbeat
    auto-recovery**, **BBR / socket tuning**. Routes arbitrary IP traffic.
  - All engines share the same AEAD encryption, mutual-auth handshake, and TCP
    tuning (`TCP_NODELAY/QUICKACK/USER_TIMEOUT`, `SO_*BUF`, BBR).
- **One-command install** — detects the distro, bootstraps Go if needed, builds a
  static binary, wires up systemd, and launches the panel.
- **Interactive panel (`et`)** — banner, live IP/geo/ASN, create wizard, and full
  lifecycle management (create/delete/restart/stop/status/logs/edit/update/info/uninstall).
- **Pluggable transports** behind one interface:
  - **`tcp`** — production-ready carrier for both engines. *(recommended)*
  - **`dns` / `ssh` / `hysteria` / `ipx`** — registered and selectable, currently
    **experimental placeholders** with documented extension points.
- **Security** — ChaCha20-Poly1305 / AES-256-GCM, HKDF-derived per-direction keys,
  HMAC challenge–response auth with fresh server nonce (replay-resistant),
  handshake flood shedding, `0600` configs, hardened systemd unit.
- **Resource discipline** — cgroup-aware worker sizing, pooled 32 KiB splice
  buffers, bounded goroutines, profile-based GC tuning, soft heap limit.

## Architecture

```
cmd/et-core            daemon + helper subcommands (run/validate/version/genpsk/sysinfo/transports)
internal/config        TOML schema, dependency-free parser/writer, validation, PSK gen
internal/crypto        AEAD framed conn + mutual-auth handshake (HKDF/HMAC)
internal/transport     transport interface + registry
        /tcp           production TCP transport (tuned sockets)
        /dns /ssh /hysteria /ipx   experimental extension points
internal/forward       L4 data path: pool, control frame, entry/exit, PROXY v2, splice
internal/mux           stream multiplexer: binary framing, per-stream flow control, PING/RTT
internal/muxeng        MUX reverse engine: session pool, stream routing, PROXY v2
internal/l3            L3 data path: multi-queue TUN pump, datagram framing, batching, heartbeat
internal/tun           multi-queue TUN device (linux impl + non-linux stub)
internal/nettune       socket/kernel tuning (NODELAY/QUICKACK/USER_TIMEOUT, SO_*BUF, BBR)
internal/proxyproto    PROXY protocol v2 header builder
internal/sysinfo       CPU cores (cgroup v1/v2 aware), memory limits
internal/logx          leveled logging + size-based rotation
internal/core          wiring: config -> engine selector -> health endpoint
scripts/               install.sh, uninstall.sh, et-panel.sh (installed as `et`)
systemd/               emergency-tunnel@.service (template unit)
configs/               example.toml
```

### How a connection flows (reverse TCP)

```
user ──▶ Iran:443 (entry, listener)
              │  picks a warm pooled link established by Kharej
              │  sends OPEN{remote_port, [PROXY v2 header]}
              ▼
        Kharej (exit, dialer) ──▶ dials 127.0.0.1:<remote_port>  (e.g. Xray)
              ▲  writes PROXY v2 header (if enabled), then splices
              └─ AEAD-encrypted link the whole way
```

Who dials vs. accepts is set by **mode** (reverse ⇒ Kharej dials). Which side owns
the forwarded ports is set by **role** (Iran ⇒ entry). The two are orthogonal, so
all four combinations work. Each pooled link is owned by exactly one worker for
its lifetime — the pool size stays exact and there are no goroutine/conn leaks.

### How packets flow (L3 TUN engine)

```
app ─▶ emergency-tun (TUN, 10.10.10.1/24)
          │  kernel hashes the flow to queue i (ordering preserved)
          ▼
    reader i ─▶ [batch N packets] ─▶ AEAD link i ═══▶ peer link i ─▶ TUN queue i ─▶ peer stack
                       ▲                                                  │
                       └───────────── heartbeat every 10s ◀──────────────┘
                         (no datagram for 25s ⇒ cycle & reconnect link i)
```

`pool` sets the number of queues **and** links (keep it ≈ CPU cores). Both ends
must use the same `engine`. Pick **l4** to expose specific ports (proxy/CDN use
cases); pick **l3** to route arbitrary IP traffic between the two hosts.

## Install

```bash
curl -fsSL https://example.com/install.sh | bash
```

Or from a local checkout of this repo:

```bash
sudo ET_SRC="$(pwd)" bash scripts/install.sh
```

Requirements: a systemd Linux host. If Go isn't present the installer fetches the
official toolchain and builds a static (`CGO_ENABLED=0`) binary.

## Quick start

Run `et`, choose **Create tunnel**, and follow the wizard on **both** servers.

- **Iran (entry):** role=iran, mode=reverse, add your forwards (e.g. `443,8443`),
  generate a PSK — **copy it**.
- **Kharej (exit):** role=kharej, mode=reverse, `peer=<iran-ip>`, paste the **same** PSK.

The panel writes `/etc/emergency-tunnel/<name>.toml` and starts
`emergency-tunnel@<name>.service`.

### Manual / systemd

```bash
et-core genpsk                                   # secure pre-shared key
et-core validate --config /etc/emergency-tunnel/iran1234.toml
systemctl {start,stop,restart,status} emergency-tunnel@iran1234
journalctl -u emergency-tunnel@iran1234 -f       # or /var/log/emergency-tunnel/iran1234.log
curl -s http://127.0.0.1:9090/stats              # live counters
```

## Port forwarding syntax

| Spec         | Meaning                                   |
|--------------|-------------------------------------------|
| `2096`       | listen 2096 → remote 2096                 |
| `200-300`    | port range (same remote ports)            |
| `8000=9000`  | listen 8000 → remote 9000                 |
| `2096@pp`    | enable PROXY protocol v2 for this entry   |
| `2096@nopp`  | disable PROXY protocol for this entry     |

`proxy_protocol` sets the default; per-entry `@pp`/`@nopp` overrides it.

## Security model

- **Confidentiality/integrity:** every byte is AEAD-sealed (ChaCha20-Poly1305 or
  AES-256-GCM) in ≤16 KiB frames with per-direction keys and monotonic nonces.
- **Authentication:** HMAC-SHA256 challenge–response derived from the PSK; the
  server issues a fresh random nonce per connection, so recorded transcripts
  can't be replayed. Session keys are HKDF-derived from both nonces.
- **Abuse resistance:** bounded concurrent handshakes (flood shedding), handshake
  timeouts, per-user assignment timeout, capped PROXY header size.
- **File/permission hygiene:** configs `0600`, dirs `0750`, hardened unit
  (`NoNewPrivileges`, `ProtectSystem=strict`, minimal capabilities, `MemoryMax`).

## Status & roadmap

- ✅ TCP transport, pooling, reverse/direct, encryption, auth, PROXY v2, panel,
  installer, systemd, logging, health/stats.
- 🚧 DNS / SSH / Hysteria / IPX transports — interfaces and registry are in place;
  implementations are the next milestone (each is a drop-in behind
  `transport.Register`). L3 transports pair with a TUN device and the
  `tun_ip`/`mtu` fields.

See [PERFORMANCE.md](PERFORMANCE.md) for tuning notes.
