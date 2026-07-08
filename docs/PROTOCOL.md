# Emergency Tunnel — Protocol & Engine Architecture

Emergency Tunnel ships **three data-plane engines** behind one config, one CLI,
one installer. They share the same authenticated, encrypted link layer and
differ only in how they move bytes:

| Engine | What it is | Best for |
|--------|------------|----------|
| **`mux`** | Multiplexed TCP forwarder — many streams over a few links | Reverse proxy / CDN / gaming / thousands of connections *(recommended)* |
| **`l4`**  | Simple TCP forwarder — one link per connection | Small, simple setups; maximum interop |
| **`l3`**  | TUN IP tunnel — raw packets, multi-queue | Routing arbitrary IP traffic (VPN-style) |

All three use the same handshake and AEAD framing (below), so encryption, auth,
and replay protection are identical across engines.

---

## Shared link layer (all engines)

Every tunnel link is a TCP connection wrapped with:

1. **Mutual-auth handshake** (`internal/crypto`): HMAC-SHA256 challenge–response
   derived from the PSK, with a fresh server nonce per connection (replay-proof).
   Session keys are HKDF-derived per direction.
2. **AEAD framing**: ChaCha20-Poly1305 or AES-256-GCM, ≤16 KiB frames, monotonic
   nonces, per-direction keys.
3. **Socket tuning** (`internal/nettune`): `TCP_NODELAY`, `TCP_QUICKACK`,
   `SO_SNDBUF`/`SO_RCVBUF` (profile-sized), `TCP_USER_TIMEOUT`, keepalive, and
   BBR congestion control (best-effort).

---

## The `mux` engine (next-generation reverse tunnel)

The `mux` engine is the headline of v1.2. Instead of opening a fresh TCP + crypto
handshake for every user connection (the `l4` model), it multiplexes **many
logical streams over a small pool of long-lived links**.

### Why it's faster

A new user connection is a single **SYN frame** on an already-open, already-
authenticated link — **zero extra round-trips**. On a long-distance link the
handshake you avoid is worth 1–2 RTT *per connection*:

| Connection setup | `mux` | per-conn handshake (`l4` cold) |
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

## Choosing an engine

- **Reverse proxy / Xray / many short connections / gaming** → `mux`.
- **A couple of long-lived TCP tunnels, simplest possible** → `l4`.
- **Route all IP traffic between two hosts (VPN-style)** → `l3`.

Both ends of a tunnel **must use the same engine**, PSK, and cipher. Engines do
not interoperate with each other.

---

## Migration

- **New tunnels**: pick `mux` in the panel (option 1) or set `engine = "mux"`.
- **Existing `l4` tunnels**: they keep working unchanged (`l4` is still fully
  supported). To upgrade one to `mux`, set `engine = "mux"` on **both** ends and
  restart both services. Configs are otherwise identical; you can lower `pool`
  to 2–4 since each session now carries many streams.
- No PSK/cipher changes are needed. Nothing about the handshake or encryption
  changed, so your keys stay valid.
