# Emergency Tunnel — Protocol & Engine Architecture

Emergency Tunnel ships **three tunnel protocols** behind one config, one CLI, one
installer. They share the same encrypted link layer and differ only in how they
move bytes:

| Protocol (engine) | What it is | Best for |
|-------------------|------------|----------|
| **TCP Reverse Tunnel (`mux`)** | Multiplexed TCP — many user streams over a few links | Reverse proxy / CDN / gaming / thousands of connections *(recommended, default)* |
| **TUN (`tun`)** | Virtual network interface — all IP traffic over a private subnet | Routing arbitrary IP (TCP/UDP/ICMP/ICMPv6) between two hosts, VPN-style |
| **SPF (`spf`)** *(beta)* | TUN + IPX encapsulation with source-IP spoofing (ICMP/TCP) | DPI evasion where plain traffic is fingerprinted (Linux + `CAP_NET_RAW`) |

Both use the same ephemeral-X25519 handshake and AEAD framing (below), so
encryption is identical. (`l3` is accepted as a deprecated alias for `tun`.)

---

## Shared link layer (all engines)

Every tunnel link is a TCP connection wrapped with:

1. **Ephemeral key exchange** (`internal/crypto`): an X25519 ECDH handshake
   (fresh keys per connection → forward secrecy; **no pre-shared key**). Session
   keys are HKDF-derived per direction from the ECDH shared secret. The exchange
   is unauthenticated — firewall the tunnel port to the peer's IP.
2. **AEAD framing**: ChaCha20-Poly1305 or AES-256-GCM, monotonic nonces,
   per-direction keys. A frame is `[uint16 len][ciphertext||tag]` and reaches the
   wire in **one write syscall** — the length prefix is sealed into the same
   buffer, never written separately (with `TCP_NODELAY` on, a separate 2-byte
   write puts a 2-byte segment in front of every frame). Frames carry up to
   63 KiB, so a full L3 packet batch or a coalesced mux write is one frame, one
   seal and one syscall instead of four. On the read side a frame is decrypted in
   place and undelivered bytes are handed out as a slice of that buffer, so no
   plaintext is ever copied twice.
3. **Socket tuning** (`internal/nettune`): `TCP_NODELAY`, profile-sized
   `SO_RCVBUF` (`SO_SNDBUF` is left to kernel autotuning on purpose),
   **`TCP_NOTSENT_LOWAT`**, `TCP_USER_TIMEOUT`, keepalive, and BBR congestion
   control (best-effort).

   `TCP_NOTSENT_LOWAT` is the load-bearing one for latency. Without it the kernel
   grows the send queue to a full bandwidth-delay product and will happily accept
   megabytes of application data on a congested path. Anything already handed to
   the kernel is out of reach of the tunnel's scheduler, so a packet classified
   as latency-critical still ends up behind whatever bulk data the kernel took a
   moment earlier. Capping the un-transmitted backlog at 128 KiB keeps the queue
   where the tunnel can still reorder and manage it.

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

### The egress scheduler

Every stream on a session shares one carrier link, so the order frames leave in
*is* the quality-of-service policy. A plain FIFO makes two things go wrong at
once: the queue grows until it hides seconds of latency, and one bulk stream's
backlog sits in front of every other stream's data.

The writer therefore runs a scheduler with four rules:

| Class | Served | Why |
|-------|--------|-----|
| Window-update credit | first, coalesced per stream | it is what unblocks the peer's sender; delaying it costs throughput in the *other* direction |
| Control (SYN/RST/PING/GOAWAY) | next | tiny, and a new stream's setup should not queue behind bulk |
| `@ll` streams | next, round-robin | low-latency forwards (gaming, SSH) |
| Bulk streams | last, round-robin | fair share between transfers |

Two properties matter beyond the ordering:

- **The DATA classes are bounded by bytes (256 KiB), not frame count.** Past the
  budget `Stream.Write` blocks, which stops draining the user's socket and
  applies TCP backpressure to the user. For a reliable stream this is strictly
  better than dropping — the opposite of the TUN data plane, where the kernel
  hands us packets whether we want them or not and CoDel must drop instead.
- **Window-update credit is accumulated, not queued.** Credit is additive, so
  coalescing is exact, and it means a window update can never be dropped for
  lack of queue space. Losing one is not a hiccup: it strands that stream's
  sender permanently.

`FIN` travels on its stream's DATA queue rather than the control class. It
consumes sequence space, so overtaking buffered data would truncate the stream —
a test drives 1 MiB followed by an immediate `Close()` and fails if any byte is
lost.

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
- **Priority + AQM scheduler** (`internal/l3/sched.go`) on every queue — see
  below. This is what keeps ping flat while a download runs.
- **Batching:** the TX path coalesces packets into ≤60 KiB AEAD frames (one
  frame, one syscall). Batching is *opportunistic*, not timer-driven: packets
  accumulate while the queue has more to give and the batch is flushed the
  instant it runs dry. A single packet on an idle tunnel therefore goes out
  immediately, while a saturated tunnel fills whole frames — no fixed flush timer
  taxing every packet.
- **Zero-allocation data path:** one persistent reader per queue reads straight
  into a pooled buffer that is handed to the scheduler and recycled after
  framing. The packet-carrier demultiplexers (UDP/ICMP/SPF) pool their buffers
  too. Steady-state allocation on the hot path is zero.
- **Liveness + RTT:** control frames measure the *link's* real round trip (shown
  as `rtt_ms` on `/stats`) and detect a dead link within ~12 s. Comparing
  `rtt_ms` against a ping through the tunnel tells you immediately whether extra
  latency is the path or queueing.
- **Auto-reconnect** per link, with sub-second first retries; a clear "Tunnel
  connected successfully: Iran 10.10.10.1 <-> Foreign 10.10.10.2" line is logged
  once the first link is up. Whatever is still queued when a link dies is
  discarded rather than delivered late after the reconnect.
- **Validation:** `tun_ip` must be a valid IPv4 CIDR; `peer_tun_ip` must be a
  valid IP inside the same subnet and different from `tun_ip`; optional `tun_ip6`
  must be a valid IPv6 CIDR.

Requires `CAP_NET_ADMIN` (granted by the systemd unit) to create the device.

### The transmit scheduler — why ping stays flat

The TUN transmit path is where the tunnel queues: the kernel supplies packets at
local NIC speed while the carrier drains them at whatever the intercontinental
path allows. A plain FIFO makes that gap hurt — a 256-packet queue is ~350 KB of
backlog, and on a 20 Mbit path that is ~140 ms of delay added to *every* packet,
interactive or not. That is the mechanism behind a ping that sits at 97 ms and
then jumps to 400 ms whenever a transfer starts.

Each queue therefore runs two mechanisms instead of a FIFO:

**Two service classes.** Latency-critical packets go to an express ring that is
always drained first, so they never wait behind a bulk backlog:

| Class | Traffic |
|-------|---------|
| express | ICMP/ICMPv6, TCP with no payload (pure ACK, SYN, RST), UDP ≤ 192 B (DNS, QUIC ACKs, VoIP, game traffic, WireGuard handshakes), any packet ≤ 128 B |
| bulk | everything else |

The split is deliberately conservative about reordering, because packets in
different classes can overtake each other and TCP reads reordering as loss.
Only traffic where overtaking is provably harmless is expedited: ICMP and UDP
have no ordering contract, and a TCP segment with no payload carries nothing a
later segment could arrive before. A **FIN is explicitly never expedited** — it
consumes sequence space, and delivering it ahead of queued data would truncate
the stream. Expediting pure ACKs is not only safe but actively raises throughput:
it keeps the inner connection's ACK clock steady, which is what lets it reach
full rate.

**CoDel AQM** (RFC 8289) on the bulk ring. Rather than letting the backlog grow
until the queue is full, CoDel measures how long packets actually sit in the
queue and starts dropping once the *sojourn time* stays above 5 ms for a full
100 ms interval. Inner TCP reads those drops as the congestion signal it is
waiting for and settles at a rate that keeps the queue short — full throughput,
no standing delay. A non-zero, steady `tx_dropped` on `/stats` under load is the
controller working, not a fault.

The same idea is applied at the two other places a queue can hide: the TUN
device gets `fq_codel` and a short `txqueuelen` (per-flow fairness on the way in,
so one download cannot delay an interactive session), and the carrier socket gets
`TCP_NOTSENT_LOWAT` (so the kernel cannot hoard what the scheduler should be
managing).

### TUN carrier modes (`tun_mode`)

How the encrypted link between the two servers' public IPs is carried. The inner
TUN traffic is identical in all modes; only the envelope changes.

| `tun_mode` | Carrier | Crypto | Status |
|-----------|---------|--------|--------|
| **`tcp`** *(default)* | reliable TCP stream | stream AEAD (`SecureConn`, sequential nonce) | production |
| **`udp`** | UDP datagrams | **datagram AEAD** (explicit 8-byte per-packet nonce) + retransmitted handshake | production |
| **`icmp`** | inside ICMPv4 echo (ping) | datagram AEAD | **beta** — Linux, `CAP_NET_RAW` |
| **`bip`** | inside ICMPv6 echo | datagram AEAD | **beta** — Linux, `CAP_NET_RAW` |

- **Datagram carriers** (`udp`/`icmp`/`bip`) use a connectionless AEAD: each
  packet carries its own counter, so loss/reordering is tolerated (fine for a
  TUN, whose inner IP traffic already retransmits). A 1024-counter sliding
  **anti-replay window** rejects duplicated and replayed datagrams while still
  accepting the reordering a real path produces. A datagram that fails to
  authenticate is *skipped*, never fatal — on an open UDP/ICMP port anyone can
  inject a packet, and tearing the tunnel down for each one would be a free
  denial of service. The handshake retransmits until the peer replies. One
  carrier datagram holds one full inner packet (the batcher caps a frame at
  ~1400 B so it fits under a 1500-byte path MTU).
- **ICMP/BIP** send Echo Requests from the dialer and Echo Replies from the
  listener, demultiplexed by (source IP, ICMP id). On the **listener** set
  `sysctl -w net.ipv4.icmp_echo_ignore_all=1` (or the icmpv6 equivalent) so the
  kernel does not also auto-reply. These modes mimic ping and are useful where
  TCP/UDP are filtered, but are **beta** — validate on a Linux host before
  production use.

> **Direction:** the tunnel is always **reverse** (Foreign dials Iran). The old
> "direct" mode was removed.

## The SPF protocol (`spf`) — beta

SPF is the TUN engine plus **IPX-style encapsulation with source-IP spoofing**.
It builds the same private `10.10.10.0/24` interface, but wraps the encrypted
frames in an L4 envelope (ICMP echo or a bare TCP segment) whose **IP source is
rewritten** to `spoof_src_ip`, routed to the peer's real IP (`peer`). It is a
**point-to-point** tunnel between two servers you control — inbound packets are
accepted only when their source is `spoof_dst_ip` (the peer's spoofed source), so
this is a configured tunnel endpoint, not a general spoofing tool.

- **Reversed on the two sides:** Iran uses `spoof_src=Iran, spoof_dst=Foreign`;
  Foreign uses `spoof_src=Foreign, spoof_dst=Iran`. Both sides need the other's
  real IP in `peer`.
- **Profiles — both spoof the source IP:** `icmp` demultiplexes links by the
  echo `id`; `tcp` sends bare TCP segments (source port demultiplexes links) with
  a spoofed IP header. Both go through the same raw-socket carrier; only the L4
  envelope differs.
- **Crypto/link reuse:** SPF reuses the same datagram AEAD, handshake, batching,
  heartbeat, and reconnect as the UDP/ICMP carriers; only the packet envelope and
  the spoofed IP header differ (built with `x/net/ipv4.RawConn`).
- **Requirements:** Linux + `CAP_NET_RAW`. On the `icmp` profile also
  `sysctl -w net.ipv4.icmp_echo_ignore_all=1` on both hosts. On the `tcp` profile
  drop the kernel's RST for the unsolicited segments on both hosts:
  `iptables -A OUTPUT -p tcp --sport <tunnel_port> --tcp-flags RST RST -j DROP`.
- **Validation:** `spoof_src_ip`/`spoof_dst_ip` must be valid IPs and differ;
  `spf_profile ∈ {icmp, tcp}`; the TUN addressing checks also apply.

> **Beta:** compiled and cross-built for Linux with the framing unit-tested, but
> the raw-socket path is **not runtime-verified in CI**. Validate on a real Linux
> host before production. TCP-Reverse and TUN(tcp/udp) are the production paths.

## Port forwarding (TUN / SPF)

The `mux` engine forwards at the application layer (it dials the remote for each
listen port). The `tun` and `spf` engines are routed L3 interfaces, so they
forward a port with kernel NAT instead. Set `forwards` on the tunnel and the
daemon installs, per listen port and for **both TCP and UDP**:

```
# listen port P on this host -> peer_tun_ip:P' across the tunnel
iptables -t nat -A PREROUTING  -p <proto> --dport P         -m comment --comment et:<name> -j DNAT --to-destination <peer_tun_ip>:P'
iptables       -A FORWARD      -p <proto> -d <peer_tun_ip> --dport P' -m comment --comment et:<name> -j ACCEPT
iptables       -A FORWARD      -p <proto> -s <peer_tun_ip> --sport P' -m comment --comment et:<name> -j ACCEPT
iptables -t nat -A POSTROUTING -o <iface> -p <proto> -d <peer_tun_ip> --dport P' -m comment --comment et:<name> -j MASQUERADE
```

- **Config:** the same `forwards` syntax as `mux` — `"443"`, `"443,8443"`,
  `"200-300"`, `"8000=9000"`. A valid `peer_tun_ip` is required as the DNAT
  target; ports are validated 1–65535.
- **Lifecycle:** rules are applied when the interface comes up and removed on
  shutdown, so `systemctl restart` and reboot restore them (they are tied to the
  tunnel process). Every apply first sweeps the tunnel's own rules by their
  comment tag `et:<name>`, so re-applies never duplicate and never touch other
  tunnels' or hand-written rules. Delete also runs `et-core firewall-down` as a
  safety net for an ungraceful kill.
- **Forwarding sysctl:** the panel enables and persists `net.ipv4.ip_forward=1`
  (`/etc/sysctl.d/99-emergency-tunnel.conf`) when a forwarding tunnel is created;
  the hardened unit (`ProtectKernelTunables=true`) intentionally can't set it
  itself.
- **Peer side:** forwarding is a routed relay to `peer_tun_ip:P'` — the peer must
  have the service listening on that port (on its tunnel IP or `0.0.0.0`).

> Linux-only (iptables/netfilter), using the daemon's existing `CAP_NET_ADMIN`.
> The rule generation is unit-tested; validate the live iptables path on a real
> Linux host.

## Health / stats port

Kept, and **local-only** by design. `et-core` serves `/health` and `/stats` on
`127.0.0.1:<health_port>` (default `9090`) — used by the panel's status view and
for debugging (live sessions/streams, rx/tx bytes, RTT, link errors, reconnects).
It never listens on a public address, and validation rejects
`health_port == tunnel_port`. Set `health_port = 0` to disable it entirely.

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
