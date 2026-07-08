# Emergency Tunnel — Protocol & Engine Architecture

Emergency Tunnel ships **two tunnel protocols** behind one config, one CLI, one
installer. They share the same encrypted link layer and differ only in how they
move bytes:

| Protocol (engine) | What it is | Best for |
|-------------------|------------|----------|
| **TCP Reverse Tunnel (`mux`)** | Multiplexed TCP — many user streams over a few links | Reverse proxy / CDN / gaming / thousands of connections *(recommended, default)* |
| **TUN (`tun`)** | Virtual network interface — all IP traffic over a private subnet | Routing arbitrary IP (TCP/UDP/ICMP/ICMPv6) between two hosts, VPN-style |

Both use the same ephemeral-X25519 handshake and AEAD framing (below), so
encryption is identical. (`l3` is accepted as a deprecated alias for `tun`.)

---

## Shared link layer (all engines)

Every tunnel link is a TCP connection wrapped with:

1. **Ephemeral key exchange** (`internal/crypto`): an X25519 ECDH handshake
   (fresh keys per connection → forward secrecy; **no pre-shared key**). Session
   keys are HKDF-derived per direction from the ECDH shared secret. The exchange
   is unauthenticated — firewall the tunnel port to the peer's IP.
2. **AEAD framing**: ChaCha20-Poly1305 or AES-256-GCM, ≤16 KiB frames, monotonic
   nonces, per-direction keys.
3. **Socket tuning** (`internal/nettune`): `TCP_NODELAY`, `TCP_QUICKACK`,
   `SO_SNDBUF`/`SO_RCVBUF` (profile-sized), `TCP_USER_TIMEOUT`, keepalive, and
   BBR congestion control (best-effort).

---

## The `mux` engine (next-generation reverse tunnel)

The `mux` engine is the headline of v1.2. Instead of opening a fresh TCP + crypto
handshake for every user connection (a naive per-connection model), it multiplexes **many
logical streams over a small pool of long-lived links**.

### Why it's faster

A new user connection is a single **SYN frame** on an already-open, already-
authenticated link — **zero extra round-trips**. On a long-distance link the
handshake you avoid is worth 1–2 RTT *per connection*:

| Connection setup | `mux` | per-conn handshake (naive model) |
|---|---|---|
| local link | 19.9 µs · 16 allocs | 32.1 µs · 133 allocs |
| 20 ms link | **32.8 ms** | **76.5 ms** |

(from `go test -bench` in `internal/muxeng`; the gap widens with distance and is
independent of how many connections are already open.)

### Frame format

Fixed 10-byte binary header, big-endian:

```
 0        1        2      3      4      5      6      7      8      9
+--------+--------+------+------+------+------+------+------+------+------+
|  type  | flags  |        streamID (u32)     |         length (u32)      |
+--------+--------+------+------+------+------+------+------+------+------+
| payload[length] ...
```

Types: `DATA(0) SYN(1) WINDOW_UPDATE(2) FIN(3) RST(4) PING(5) GOAWAY(6)`.
- **SYN** payload carries the destination hint (remote port + optional PROXY-v2
  header) so the exit can dial the right local service.
- **WINDOW_UPDATE** uses the `length` field as a credit increment.
- **PING** carries an id in `streamID` and 8 opaque bytes for RTT measurement.

### Flow control (no head-of-line blocking)

Each stream has an independent **256 KiB receive window**. A sender may only have
that many unacknowledged bytes in flight per stream; the receiver returns
`WINDOW_UPDATE` credit as the application consumes data. Consequences:

- A slow or stalled stream **cannot stall other streams** — its window drains and
  only *that* stream's writer blocks.
- Buffers are bounded by the window, so RAM stays flat under load.

### Write scheduling & adaptive batching

A single writer goroutine per session drains a **two-class priority queue**
(high / normal) and **coalesces whatever is queued into one `Write`**. This is
adaptive batching for free: light load writes one frame (low latency), heavy load
packs many frames per syscall (high throughput, low CPU).

### Health & fast recovery

Each session runs a **PING keepalive** (`heartbeat_interval`) and measures RTT. A
session with no reply within `heartbeat_timeout` is torn down; the dialing side
reconnects with backoff. The `/stats` endpoint reports live sessions, stream
counts, byte counters, and the best current RTT — so degradation is visible
before users notice.

### Resource profile

A handful of sessions replace hundreds of sockets: far fewer file descriptors,
goroutines, and kernel buffers. Payload copies use a `sync.Pool`; steady-state
allocations on the data path are ~6/op (see throughput benchmark: ~1.7 GB/s on a
single in-memory stream).

---

## The TUN protocol (`tun`)

TUN mode creates a **virtual network interface** (`emergency-tun`) on each
server and carries **raw IP packets** between them over the encrypted links. The
two hosts get private addresses on a shared subnet (default `10.10.10.0/24`:
Iran `10.10.10.1`, Foreign `10.10.10.2`) and can then reach each other on those
IPs with **any** IP protocol — TCP, UDP, ICMP (ping), and IPv6 ICMP.

- **Multi-queue** TUN: `pool` queues, each paired 1:1 with an encrypted link.
  The kernel hashes each flow to a fixed queue, so per-flow ordering is preserved
  while load spreads across CPU cores.
- **Batching:** the TX path coalesces packets into ≤16 KiB AEAD frames to cut
  syscalls and CPU; a 2 ms flush bounds latency at low rates.
- **Zero-copy-ish:** one persistent reader per queue with a `sync.Pool` of packet
  buffers; steady-state allocation is minimal.
- **Heartbeat + auto-reconnect** per link; a clear "Tunnel connected
  successfully: Iran 10.10.10.1 <-> Foreign 10.10.10.2" line is logged once the
  first link is up.
- **Validation:** `tun_ip` must be a valid IPv4 CIDR; `peer_tun_ip` must be a
  valid IP inside the same subnet and different from `tun_ip`; optional `tun_ip6`
  must be a valid IPv6 CIDR.

Requires `CAP_NET_ADMIN` (granted by the systemd unit) to create the device.

---

## Choosing a protocol

- **Reverse proxy / Xray / many short connections / gaming** → **TCP Reverse (`mux`)**.
- **Route arbitrary IP traffic (ping, UDP apps, IPv6) between two hosts** → **TUN (`tun`)**.

Both ends of a tunnel **must use the same protocol** and cipher; they do not
interoperate with each other.

---

## Migration

- **New tunnels**: the panel offers TCP Reverse (option 1, default) and TUN
  (option 2). Or set `engine = "mux"` / `engine = "tun"` in the config.
- **Upgrading from an older version**: the removed `l4` (simple forwarder)
  engine no longer exists — re-create those tunnels as `mux` (same `forwards`).
  The `l3` engine value is still accepted as an alias for `tun`.
- No key management is needed — encryption keys are ephemeral (auto-negotiated
  per connection). There is no pre-shared key to configure or rotate.
