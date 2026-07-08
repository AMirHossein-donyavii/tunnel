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

- **Two tunnel protocols** (choose per tunnel — see [docs/PROTOCOL.md](docs/PROTOCOL.md)):
  1. **TCP Reverse Tunnel (`mux`)** — many user connections become lightweight
     **streams over a few long-lived links**. A new connection costs one SYN
     frame (no extra handshake) → **lowest latency**, scales to thousands of
     connections. Per-stream **flow control**, priority scheduling, adaptive
     batching, PING/RTT health. *(recommended, default)*
  2. **TUN (`tun`)** — a **virtual network interface** between the two servers
     (multi-queue TUN device). All IP traffic flows over the tunnel subnet
     (default `10.10.10.0/24`; Iran `10.10.10.1`, Foreign `10.10.10.2`).
     Selectable **carrier mode** (`tun_mode`): **`tcp`** (default) · **`udp`**
     (low overhead) · **`icmp`** / **`bip`** (ICMP / ICMPv6 mimicry — *beta*,
     Linux + `CAP_NET_RAW`). Packet batching, heartbeat auto-recovery, BBR/socket
     tuning.
  - Both protocols share the same AEAD encryption, ephemeral X25519 key exchange,
    and TCP tuning (`TCP_NODELAY/QUICKACK/USER_TIMEOUT`, `SO_*BUF`, BBR).
- **One-command install** — detects the distro, bootstraps Go if needed, builds a
  static binary, wires up systemd, and launches the panel.
- **Interactive panel (`et`)** — banner, live IP/geo/ASN, create wizard, and full
  lifecycle management (create/delete/restart/stop/status/logs/edit/update/info/uninstall).
- **Pluggable transports** behind one interface:
  - **`tcp`** — production-ready carrier for both engines. *(recommended)*
  - **`dns` / `ssh` / `hysteria` / `ipx`** — registered and selectable, currently
    **experimental placeholders** with documented extension points.
- **Security** — ChaCha20-Poly1305 / AES-256-GCM with **ephemeral X25519** key
  exchange (forward secrecy, no pre-shared key), HKDF-derived per-direction keys,
  handshake flood shedding, `0600` configs, hardened systemd unit. *(Encryption
  is unauthenticated — firewall the tunnel port to the peer IP; see Security model.)*
- **Resource discipline** — cgroup-aware worker sizing, pooled 32 KiB splice
  buffers, bounded goroutines, profile-based GC tuning, soft heap limit.

## Architecture

```
cmd/et-core            daemon + helper subcommands (run/validate/version/sysinfo/transports)
internal/config        TOML schema, dependency-free parser/writer, validation
internal/crypto        AEAD framed conn + ephemeral X25519 key exchange (HKDF)
internal/transport     transport interface + registry
        /tcp           production TCP transport (tuned sockets)
        /dns /ssh /hysteria /ipx   experimental extension points
internal/mux           stream multiplexer: binary framing, per-stream flow control, PING/RTT
internal/muxeng        TCP Reverse engine: session pool, stream routing, PROXY v2
internal/l3            TUN engine: multi-queue TUN pump, datagram framing, batching, heartbeat
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

The tunnel is always **reverse**: the Foreign (Kharej) server dials the Iran
server (which owns the user-facing/tunnel ports). Each pooled link/session is
owned by exactly one worker for its lifetime — the pool size stays exact and
there are no goroutine/conn leaks.

### How packets flow (TUN engine)

```
app ─▶ emergency-tun (TUN, 10.10.10.1/24)   any IP: TCP/UDP/ICMP/ICMPv6
          │  kernel hashes the flow to queue i (ordering preserved)
          ▼
    reader i ─▶ [batch N packets] ─▶ AEAD link i ═══▶ peer link i ─▶ TUN queue i ─▶ peer stack
                       ▲                                                  │
                       └───────────── heartbeat every 10s ◀──────────────┘
                         (no datagram for 25s ⇒ cycle & reconnect link i)
```

`pool` sets the number of queues **and** links (keep it ≈ CPU cores). Both ends
must use the same protocol. Pick **TCP Reverse (`mux`)** to expose specific
ports (proxy/CDN use cases); pick **TUN (`tun`)** to route arbitrary IP traffic
(TCP/UDP/ICMP/ICMPv6) between the two hosts over `10.10.10.0/24`.

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

- **Iran (entry):** role=iran, mode=reverse, tunnel port `1234`, add your listen
  ports (e.g. `443`). Encryption is automatic — no key to share.
- **Kharej (exit):** role=kharej, mode=reverse, `peer=<iran-ip>`, same tunnel
  port `1234`. No listen port on this side.

The panel writes `/etc/emergency-tunnel/<name>.toml` and starts
`emergency-tunnel@<name>.service`.

> **Both ends must use the same tunnel port.** Encryption keys are negotiated
> automatically per connection (ephemeral X25519) — there is no pre-shared key.
> Because that means no peer authentication, **restrict the tunnel port to the
> peer's IP** in your firewall (see Security model).

### Manual / systemd

```bash
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
- **Key exchange:** ephemeral **X25519** per connection — session keys are
  HKDF-derived from the ECDH shared secret. No pre-shared key to manage or leak,
  and every connection gets fresh keys (**forward secrecy**).
- **Authentication (important):** the ephemeral exchange is **unauthenticated** —
  it protects against passive eavesdropping/DPI (the primary censorship threat)
  but not an active man-in-the-middle. **Mitigation:** restrict the tunnel port
  to the peer's IP with a firewall, e.g.
  `ufw allow from <PEER_IP> to any port 1234 proto tcp` (and deny it otherwise).
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
