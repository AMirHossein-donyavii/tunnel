# Reference Analysis & Improvements

The two supplied references were studied for architecture and UX only. Emergency
Tunnel is an **original, clean-room** implementation — no code was copied.

## What the references were

| Reference | What it is | What we learned |
|-----------|------------|-----------------|
| `backhaul.sh` + `backhaul_premium` | Obfuscated commercial *Backhaul* tunnel (Go core + bash manager, TOML configs, mux, multiple transports, per-tunnel systemd). | The product shape: a small Go core driven by a rich interactive bash panel; TOML per tunnel; transports selectable at create time; banner + server identity display. |
| `manage.sh` | Lightweight ICMP "spoof-tunnel" manager: menu, `icmp-@<name>` template units, per-tunnel JSON + `.log`, core-update flow. | The lifecycle menu (create/manage/status/logs/restart/delete) and the systemd-template-per-tunnel pattern. |
| `bypass.sh` | A **license crack** for Backhaul (machine-id spoof + binary patch). | **Deliberately not reproduced** — it is piracy of a third-party binary and irrelevant to an original product. |

## Concrete improvements

**Architecture**
- Real Go module with a clean, testable package layout instead of one monolithic
  script wrapping an opaque binary.
- A single pluggable `transport.Transport` interface: the crypto handshake,
  pooling and forwarding are written once and every transport inherits them.
- Each pooled link is owned by exactly one worker for its lifetime → the pool
  size is exact, with no goroutine/connection leaks (a common failure mode in
  hand-rolled pools).

**Security** (the references relied on a proprietary binary; `bypass.sh` actively
*weakened* integrity checks)
- Modern AEAD (ChaCha20-Poly1305 / AES-256-GCM), per-direction HKDF keys,
  monotonic nonces.
- Mutual HMAC challenge–response auth with a fresh server nonce per connection →
  replay-resistant by construction.
- Handshake flood shedding, handshake/assignment timeouts, `0600` configs, and a
  hardened systemd unit (minimal capabilities, `ProtectSystem=strict`,
  `MemoryMax`, `NoNewPrivileges`).

**Resource efficiency** (explicit goal for 2-core / 2–4 GB VPS)
- cgroup v1/v2-aware `GOMAXPROCS` and worker sizing.
- Pooled 32 KiB splice buffers and reusable per-connection frame buffers → near
  zero steady-state allocation.
- Profile-driven GC + soft heap limit tied to the cgroup memory limit.

**Operations**
- `et-core validate` as an `ExecStartPre` gate so a bad edit can't silently
  crash-loop a service.
- Structured, rotating logs **and** journald; a localhost `/health` + `/stats`
  endpoint for real connection statistics.
- One idempotent installer that detects the distro, bootstraps Go if needed,
  builds a static `CGO_ENABLED=0` binary, and verifies the result.

**Correctness fixes over naive designs**
- Guard against forwarding a port that collides with the tunnel `listen_port`
  in reverse mode (where Iran binds both).
- PROXY protocol v2 support so exit-side services still see the real client IP.
