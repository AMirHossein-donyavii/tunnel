# Changelog

All notable changes to Emergency Tunnel are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/), and the
project uses [Semantic Versioning](https://semver.org/).

## [2.13.3] — 2026-08-15

Both of these are fixes to the diagnostic itself. It was being used to find a
throughput problem and it was giving wrong answers.

### Fixed

- **The health line reported `needed=18446744073709549315`.** It subtracted two
  duplicate counters from each other to guess how many second copies the path
  had needed. That subtraction means nothing: one counts copies this side
  *sent*, the other counts copies this side *received and discarded*, which are
  different directions at different rates — and on an unsigned counter it
  wrapped. Both are now reported as they are, `dup_sent` and `dup_recv`.

- **`aqm_dropped` was three different things added together.** AQM dropping to
  signal congestion, a ring with no room left, and an express packet overtaken
  by a fresher one were one counter. Those have three different causes and three
  different fixes, and telling them apart is the only reason the line exists. The
  health line now reads `aqm_dropped=… queue_full=… stale=…`, and the stats
  endpoint gains `aqm_dropped`, `queue_full_dropped` and `stale_dropped`.

  This mattered immediately: a run with the AQM switched off still reported
  thousands of "aqm_dropped", because those were the ring overflowing.

## [2.13.2] — 2026-08-14

### Added

- **`aqm = "off"`** turns the TUN transmit queue into a plain tail-drop FIFO.
  CoDel stays the default.

  This exists because of a measurement, not a theory. On one real route this
  tunnel sustained 120 Mbit/s with about 4,000 retransmissions while another
  implementation sustained 297 Mbit/s with 27,450 — seven times the loss and two
  and a half times the throughput. Loss is therefore not what holds this tunnel
  where it is, and neither is the code: benchmarked on loopback, the ICMP carrier
  moves 2.1 Gbit/s and the scheduler ahead of it 53 Gbit/s.

  What is left is how the drops are *shaped*. A tail-drop queue loses a burst all
  at once, which a bulk TCP flow reads as one congestion event and answers with
  one window reduction. CoDel deliberately spaces its drops out in time, and each
  spaced drop is a separate event and a separate reduction. That is the right
  trade when a queue carries interactive traffic alongside a download, and it may
  be the wrong one for a single heavy flow on a long path.

  Which of those is happening can only be answered on the path itself, so this is
  the control for that experiment: set `aqm = "off"` on both servers, run the same
  test, and compare. The priority split is unaffected — express traffic still
  jumps the bulk backlog either way, because that is not the AQM.

## [2.13.1] — 2026-08-14

### Fixed

- **Reverted the queueing-delay ceiling added in 2.13.0. It cut throughput from
  121 Mbit/s to 3.** The ceiling dropped any bulk packet older than 150 ms at
  dequeue, in a loop. Each drop looks reasonable alone; the loop meant the first
  dequeue after the queue had ever been backed up past the ceiling discarded
  every packet in it — and the next dequeue did the same to whatever inner TCP
  had just retransmitted. Purge, retransmit, refill, purge.

  The tests shipped with it asserted that stale packets were dropped, which is
  what the code did, so they passed. Two tests now assert the property that was
  actually violated: one dequeue returns one packet and removes at most a
  bounded few however far behind the queue is, and a stalled carrier coming back
  drains its backlog rather than throwing it away. Both fail on 2.13.0's code
  ("one dequeue removed 2000 of 2000 queued packets") and pass on this one.

  CoDel already bounds the standing queue, and it does so by dropping at a *rate*
  — which is the difference between a congestion signal and a wipe. If the
  standing queue is still too deep, the fix is in how CoDel is driven, not a
  second dropper competing with it.

The automatic restart of tunnels on upgrade, also from 2.13.0, is unaffected and
stays.

## [2.13.0] — 2026-08-14

### Fixed

- **An upgrade left the old core running.** The restart after an install parsed
  `systemctl list-units`, which prefixes a unit in a failed state with a bullet —
  that bullet lands in the first column, so the unit name became "●" and the
  restart was attempted on it instead. It also missed any tunnel that was enabled
  but currently stopped, which is the case an upgrade most needs to bring back.
  So the new binary was installed and none of its fixes took effect until
  someone restarted each tunnel by hand, which reads as an update that did
  nothing.

  The tunnel list now comes from the configs, which are the source of truth, and
  every tunnel that is enabled *or* active is restarted onto the new version. One
  that was deliberately stopped and disabled stays down. The install now says
  which: `restarted 3 tunnel(s) onto v2.13.0`, and names any that did not come
  back.

- **A hard ceiling on how long a bulk packet may sit in the queue.** CoDel
  controls the queue by the *rate* it drops at, and its control law ramps: the
  first drop comes an interval after the queue goes over target, and the rate
  climbs as the square root of the count. That converges, but while it is
  converging the queue can be far deeper than target — and how deep depends on
  how much room the ring gives it. Raising the ring in 2.10.1 to absorb a long
  path's burst therefore also raised the worst case: 4096 packets is five
  megabytes, which at 120 Mbit is a third of a second of standing delay.

  Bulk packets are now dropped past 150 ms regardless of what CoDel is doing.
  The bound is in time rather than bytes because that is what matters — a byte
  cap is a different amount of delay at every rate, a delay cap is the same
  promise at all of them. Past it a packet is stale: the sender has already
  decided it was lost, so delivering it costs bandwidth and helps nobody. A queue
  that is keeping up is untouched, and the express class keeps its own longer
  rule.

## [2.12.0] — 2026-08-14

### Fixed

- **One connection that opened and said nothing stopped every other peer
  connecting to a WebSocket tunnel.** The HTTP upgrade ran on the accept path,
  reading a request from a peer that had not sent one, bounded only by the
  ten-second handshake deadline. So a single TCP connection that stayed silent
  blocked the accept loop for ten seconds, and a handful of them in rotation
  stopped the tunnel accepting at all — a denial of service available to anyone
  who could reach the port, costing one goroutine per pending connection to
  remove. Upgrades now run concurrently and only finished ones are offered.
  The test for it went from failing after ten seconds to passing immediately.

### Added

- **The Basic section now offers the eight transports by name**: `tcp`,
  `tcpmux`, `xtcpmux`, `ws`, `wss`, `wsmux`, `wssmux`, `xwsmux`. `wss` and
  `wssmux` were previously reachable only through Backpack; each of the eight is
  now driven to completion by the console's own checks and verified to write the
  data plane it names.

- **`xws` and `xwss`: a WebSocket whose payload carries no signature.** Every
  connection this tunnel makes opens with the same five constant bytes,
  `45 54 02 03 03`, at offset zero of the first message. Two very ordinary
  deployments can see them: plain `ws`, where the payload is not encrypted at
  all, and `wss` behind a CDN or company proxy that terminates TLS and forwards
  the WebSocket onward. Either has a five-byte signature to match on.

  These layer the stealth handshake inside the WebSocket, so what a CDN sees is
  still an ordinary WebSocket carrying binary messages, and what is in those
  messages is uniform random bytes with no header, version or constant. A peer
  without the token gets silence rather than a reply.

  The order is deliberate: the WebSocket is outside because that is what a CDN
  has to understand and route, and the obfuscation is inside because that is
  where the thing being hidden lives. Wrapping the other way round would hide
  the WebSocket too, which defeats having one.

  A test reads the bytes that actually go over the socket and fails if the
  signature is in them, rather than trusting that a layer was added.

## [2.11.0] — 2026-08-14

The TUN carriers now use the configuration shape the field has settled on, and
gained the three knobs that shape carries which this core lacked. What is
deliberately not adopted is listed at the end.

### Changed

- **A carrier is now named the way the field names it**: an `encapsulation` of
  `"tcp"` for a real TCP stream, or `"ipx"` plus an `ipx_profile` of `icmp`,
  `ipip`, `udp`, `gre` or `bip` for the raw-IP family. `tun_mode` says the same
  thing in one word and is still accepted — every existing config keeps working
  untouched. Whichever is given is normalised into one field at validation, so
  nothing downstream can read two names and disagree with itself, and a config
  written back states both and reads the same next time. Six carriers round-trip
  through a written file in the tests.

### Added

- **`icmp_type` / `icmp_code`** set the exact ICMP message the icmp carrier
  emits and accepts, for a path that passes some type other than echo.

  Left unset — which is the default, and zero is treated as unset rather than as
  "type 0" — the carrier keeps choosing for itself, and that choice is better
  than any fixed value: it sends Echo Replies, which no kernel answers with a
  copy of the payload, and falls back to Echo Requests if the path drops
  unsolicited replies. Setting an explicit type removes the probing, which is
  meaningless once the messages are not echo.

- **`interface`** binds a raw-IP carrier's socket to one network device. These
  carriers have no ports, so the socket otherwise receives that IP protocol from
  every interface the host has — on a server with a public and a private NIC, or
  one that also terminates a real GRE tunnel, most of that is not ours and each
  packet costs a wakeup and a parse before the framing rejects it. An interface
  name that does not exist now fails at startup rather than binding nothing.

- **`listen_ip`** (from 2.10.0) does the same for a single address.

### Not adopted, and why

The parts of that configuration that measure worse here were left alone: a
10 s/25 s heartbeat where this core uses 2 s/8 s and detects a dead link three
times sooner; a 10,000-packet FIFO where this one runs 4096 behind CoDel, which
is burst absorption without the second of standing delay a queue that size has
with no AQM; no encryption at all on the stream transports; and a static
pre-shared key with no forward secrecy where this core does an ephemeral X25519
exchange per connection.

## [2.10.1] — 2026-08-14

### Fixed

- **The transmit ring was far too small to absorb a burst on a long path.** It
  held 512 packets — about 676 KB at the datagram carriers' MTU — while a
  100 Mbit path at 150 ms, which is Iran to Europe, keeps roughly 1420 packets
  in flight and inner TCP fills that. A burst arriving faster than CoDel's
  100 ms interval overflowed the ring and was tail-dropped: the crude drop CoDel
  exists to replace, costing throughput instead of signalling congestion gently.

  The ring is now 4096 packets on the fast profile and 2048 on balanced, which
  covers that path with headroom; the resource profile stays small so a tiny VPS
  caps what a sustained backlog can hold. This is only safe because there is an
  AQM in front of it — CoDel bounds how long a packet may *sit* in the queue
  whatever the capacity, so the extra depth buys burst absorption and not
  standing delay. Backhaul's equivalent is 10,000 packets with no AQM at all,
  which is 13 MB, or about a second of bufferbloat at 100 Mbit.

  Three tests hold both halves of that: the ring absorbs a 1500-packet burst with
  no drops, a drainer that keeps up never sees more than a few packets queued,
  and a drainer that cannot keep up still gets CoDel drops rather than a deep
  ring full of stale packets.

## [2.10.0] — 2026-08-14

### Added

- **Two new TUN carriers: IP-in-IP (protocol 4) and GRE (protocol 47).** These
  are the remaining IP-level protocols a router forwards without looking inside,
  and they are what site-to-site tunnels between routers are built from — so a
  path that filters TCP and UDP, and polices ICMP, frequently leaves them alone,
  because dropping them breaks ordinary infrastructure.

  Neither has ports, so both inherit the raw-socket problem the ICMP carrier
  already solved and the same answer: every frame says which direction it is
  travelling and which tunnel it belongs to, and the tunnel port — meaningless to
  these protocols, which is what makes it free to use — separates two tunnels on
  one host. Unlike an echo message there is no id field to tell the links of a
  pool apart, so the link id is carried explicitly:

      frame = [direction: 1][tunnel port: 2][link id: 2][sealed frame …]

  GRE prepends a well-formed four-byte GRE header (no extension flags, version 0,
  carrying IPv4), so anything on the path that understands GRE sees a plain GRE
  tunnel rather than something malformed to drop. IP-in-IP prepends nothing: a
  real one's payload is an opaque inner packet that routers do not inspect, so
  adding anything would only cost bytes and make it less like the real thing.

  The pool shares one raw socket with a single read loop, as the ICMP carrier
  does, because a raw socket has no port and one per link would make the kernel
  copy every packet of that protocol into every one of them.

  Verified end to end over real raw sockets, for both protocols: four links
  dialed, each accepted, each receiving its own frames and only its own.

- **`listen_ip`** binds a raw-IP carrier to one local address. A server with
  several addresses otherwise receives that IP protocol on all of them, and on a
  box running a real GRE or IP-in-IP tunnel, most of that traffic is not ours.

### Changed

- The "two tunnels sharing a tunnel port" conflict rule now covers every carrier
  with no ports of its own — icmp, bip, ipip, gre and the SPF icmp profile —
  rather than ICMP alone. The reasoning was never specific to ICMP: a raw socket
  for any IP protocol receives every packet of it.

- The console's own checks now validate with the core built from the same tree.
  They were using whatever core happened to be installed, which reported a
  builder writing a key that core predates as the console's fault.

### Note

These carriers came from reading the configuration surface of Backhaul's IPX
mode, which its own install script writes in plain text. The wire format above is
this project's, built to fit this project's engine; nothing was taken from the
compiled binary. What is deliberately *not* copied is the parts that measure
worse: a 10 s/25 s heartbeat where this core uses 2 s/8 s, a plain FIFO queue
where this one runs CoDel with an express class, no encryption at all on the
stream transports, and a static pre-shared key with no forward secrecy where this
core does an ephemeral X25519 exchange per connection.

## [2.9.1] — 2026-08-13

Stability work on the packet carriers (TUN udp/icmp/bip and SPF). All of it comes
from one observation: those carriers do not retransmit, so anything that made the
tunnel drop a packet — or worse, tear the link down — showed up as a ping through
the VPN timing out, with nothing in any log to say why.

### Fixed

- **One packet the TUN device refused killed the whole carrier link.** A device
  write can fail for reasons that have nothing to do with the path: the kernel's
  queue momentarily full (ENOBUFS), or one packet the device will not accept
  (EINVAL). The reader treated any of them as the link being dead and returned,
  which tore the carrier down and re-dialed it — hundreds of milliseconds in
  which everything was lost. A rejected packet is now one packet; only a device
  that refuses 128 in a row cycles the link, and the counter resets on the first
  success so a burst under load never accumulates.

- **A send the carrier socket refused killed the link the same way.** A raw ICMP
  socket meets this routinely: ENOBUFS when the interface queue is full, EPERM
  when a firewall rate-limiter drops one packet, EMSGSIZE for one frame the path
  will not take. All three are now one lost frame rather than a re-dial. A socket
  that refuses 256 sends in a row is still treated as broken.

- **A late express packet was dropped even when there was nothing better to
  send.** The rule was "past 250 ms, delivering it late is worse than dropping
  it" — but that is only true when a fresher packet is waiting behind it. With an
  empty queue it manufactured the exact symptom it existed to avoid: a carrier
  hiccup of a third of a second turned a ping into a timeout where delivering it
  would have shown an honest 300 ms, and cost a pure TCP ACK a full
  retransmission timeout. A stale express packet is now dropped only when it has
  been overtaken, and the bound is a second.

### Added

- **Small frames are sent twice on the packet carriers.** These carriers do not
  retransmit. Inner TCP recovers from loss on its own, but three things do not: a
  ping through the tunnel, which shows the loss directly as a timeout; a pure
  ACK, which costs the sender a round trip; and a heartbeat, whose loss is a step
  towards the liveness monitor deciding the link is dead and cycling it — the
  most visible failure there is on a path that polices ICMP.

  All three are small. Sending a frame of 256 bytes or less twice turns a loss
  rate of p into p² for exactly the traffic whose loss is felt, and costs nothing
  on a busy tunnel, where frames are full and never qualify. Measured against a
  10% loss path: **10.45% of small frames lost with one copy, 0.93% with two.**

  The copy is the same sealed bytes, not a re-seal, so the peer's replay window
  discards it for free — no duplicate packets reach the TUN device, and a
  duplicate no longer counts towards the "peer's keys do not match" limit, which
  on an idle tunnel would have walked up and torn down a healthy link.

- **A health line once a minute, silent when there is nothing to say.** Five
  distinct causes produced the same "unstable" symptom and had five different
  fixes; each was counted internally and none was ever shown. The line reports
  what changed in the last minute: reconnects, packets the device refused, sends
  the socket refused, datagrams dropped because a link was not draining, AQM
  drops, bad frames, link RTT, and how many of the duplicate small frames the
  path actually needed — which is a direct estimate of carrier loss.

  The same figures are on the stats endpoint as `tun_write_errors`,
  `carrier_write_errors`, `carrier_dropped`, `dup_sent` and `dup_dropped`.

## [2.9.0] — 2026-08-13

### Changed

- **The ICMP carrier no longer makes the listening server upload a copy of
  everything it receives.** A kernel answers an Echo Request by itself, copying
  the payload back verbatim. The dialer sent requests, so for every byte it sent,
  the listening server's kernel sent that byte straight back — the tunnel's whole
  download volume, as junk, on the server that usually has the smaller uplink.
  The real traffic in the other direction then queued behind it, which is what a
  tunnel that feels slow to update looks like from a chat app.

  Frames now go out as Echo *Replies*, which no kernel answers. Nothing in the
  protocol needed them to be requests: the direction tag, not the ICMP message
  type, is what says which way a frame is travelling. Measured here on the
  running kernel: a 1211-byte Echo Request draws 1211 bytes back, an Echo Reply
  draws nothing.

  A middlebox that drops an Echo Reply it has no matching request for would break
  this, so the dialer tries replies, falls back to requests if the link does not
  come up, and remembers which worked — no configuration, and a peer still on an
  older core is handled by the same fallback. The listening side accepts both.

- **The pool of links now shares one raw socket instead of opening one each.** A
  raw ICMP socket has no port and no filter, so the kernel copies every ICMP
  packet the host receives into every one of them: a pool of four meant four
  copies of every packet, four wakeups, four parses and three discards — work
  that grows with the square of the pool, on a server that is usually one core.
  One socket, one read loop and a map from echo id costs one copy however many
  links there are, which is how the listening side has always worked.

  Verified end to end over loopback: four links dialed, each accepted, each
  receiving its own frames and only its own.

### Note

The SPF `icmp` profile still sends Echo Requests and pays the same kernel copy.
It spoofs its source address, so the copy is not sent back to the dialer, but the
listening server's uplink still carries it. Separating the message type from the
direction tag there means changing that codec's interface, and this build has no
way to exercise SPF's spoofing end to end, so it was left alone rather than
changed untested.

## [2.8.9] — 2026-08-13

### Fixed

- **Two ICMP tunnels on one server read each other's traffic and both broke.**
  ICMP has no ports, and a raw ICMP socket receives a copy of every ICMP packet
  the host receives — not the subset addressed to one listener, because there is
  no such thing. The only field left to separate tunnels by was the echo id,
  which each dialer picks at random per link, so a listener had no way to know
  which ids were its own. On a server running two ICMP tunnels — two Foreign
  servers dialing in, different tunnel ports, different subnets, exactly what the
  console builds — each listener answered the other's peer, each dialer accepted
  those replies as its own listener's, and both links carried two interleaved
  ciphertext streams. Both tunnels degraded and neither log said why.

  The configured tunnel port now travels in every frame as the tunnel's identity.
  It means nothing to ICMP, which is what makes it free to use: both ends of a
  tunnel are configured with the same one, and two tunnels on a host with
  different ones. Each side drops what is not addressed to it. The same fix
  applies to the SPF icmp profile, which had the identical problem.

  Reproduced first — two listeners on one host, one frame, both accepted it —
  and the same test now passes.

- **Two ICMP tunnels sharing a tunnel port are now refused at creation.** That
  was previously reported only when both sides were listeners, on the reasoning
  that they would fail to bind; nothing binds an ICMP tunnel port, so a dialer
  and a listener, or two dialers aimed at different peers, passed as clean and
  then broke each other in production.

- **A peer configured with a different `tunnel_port` no longer fails silently.**
  It produces the same dropped frames as a neighbouring tunnel's traffic, but it
  means the tunnel will never come up, so it is now named in the log — with the
  port the peer is using and the one this tunnel expects — once per source per
  two minutes, since a peer retries several times a second.

## [2.8.8] — 2026-08-13

### Added

- **The installer now says when it is an old cached copy of itself.**
  `raw.githubusercontent.com` serves it with a five-minute cache, so a machine
  re-running the published one-liner shortly after a fix is handed the previous
  version and reproduces a bug that is already fixed — with nothing in the output
  to suggest that is what happened, because the version it reports is the one it
  knows about. It now carries its own version, compares it against the sources,
  and prints the cache-busting command when it is behind. The version probe it
  uses for that carries a cache-buster itself: without one, a stale script and a
  stale probe agree with each other about a version that is no longer current.

  The release build refuses to package a tree whose installer version has
  drifted, since nothing about a stale constant fails on its own.

## [2.8.7] — 2026-08-13

### Fixed

- **The module-proxy fallback added in 2.8.5 never actually ran.** The separator
  in `GOPROXY` is load-bearing and the list was written with commas: a
  comma-separated list falls through only on 404 and 410, and every other status
  is fatal. Google's module proxy answers a blocked region with **403** — exactly
  the case the mirror list exists for — so the build died on the first module it
  was refused, having never tried a single mirror. The list now uses pipes, which
  fall through on any error.

  Demonstrated both ways against a proxy that refuses everything with 403: with
  commas the build fails on the first module, with pipes it falls through and
  completes. The full installer path was then run end to end with that proxy
  placed ahead of the real ones, and built the core.

- **`direct`, the last entry in that list, fetches with git over HTTPS** and so
  carried the same unbounded hang that used to stop the clone. It is now bounded
  by git's low-speed limits, and git is told never to prompt.

- A build that fails on 403s now says what a 403 from a module proxy means and
  gives the one-line override for it.

## [2.8.6] — 2026-08-13

### Fixed

- **The source build hung indefinitely at "cloning …".** `git clone` against a
  filtered host has no timeout of its own, so the installer stopped dead with
  the cursor under that line and never came back — worse than any error, because
  there is nothing to read and nothing to do. The sources now come as an archive
  over ordinary HTTPS with the same bounded options as every other download here:
  a tenth of the size of a clone, no `git` needed at all, and served by
  `codeload.github.com`, a different host from the one the clone talks to, so it
  can answer where the clone hangs. A clone remains the last try, now with a hard
  time limit. Verified end to end: sources fetched, `v2.8.6` built, with `git`
  forced to fail throughout.

- **`--local` on a path that does not exist said the file was "neither a
  directory nor a tarball"**, which describes the wrong problem — the file was
  simply not there. It now says so and shows how to copy the release across.

## [2.8.5] — 2026-08-13

### Fixed

- **The source build — the installer's last resort — depended on two Google
  hosts, on exactly the paths where it is the only option left.** The toolchain
  came from `go.dev`, whose download redirects to Google's file host; on a
  filtered path that redirect is answered by the filter, so the step failed with
  a bare `404` and `cannot download Go` rather than anything an operator could
  act on. Module downloads then went through Google's module proxy, which is a
  second host with the same problem.

  The distribution's Go is now tried first: it arrives over the package mirror
  the installer has already used successfully by that point, and it is signed.
  Its version is checked against what the sources actually need, so a toolchain
  too old to build the tree is rejected here with a clear reason instead of
  failing deep in the compiler. `go.dev` remains the fallback, and module
  downloads fall back to mirrors after Google's proxy — safe whichever answers,
  because every module is checked against the hashes in `go.sum`, so a proxy can
  serve the build or fail but cannot change what gets compiled.

- **A dead end now says what to do.** When the release host, the GitHub API and
  `go.dev` are all unreachable — which is one machine's ordinary situation, not a
  rare one — the installer used to stop at `cannot download Go`. It now names
  the situation and points at `--local`, the path that needs no network at all.
  The same guidance is attached to a failed clone and a failed build.

## [2.8.4] — 2026-08-13

### Fixed

- **The installer looked hung at "Release" for a minute on a path where the
  release host is filtered.** Resolving a version fetches a few bytes and is
  allowed to fail — that is the whole point of trying several sources — but it
  was doing so with the download options: four attempts, fifteen seconds of
  connect timeout each. Against a host that accepts TCP and never completes TLS,
  measured here, that is 66 seconds of silence under a bare "Release" heading
  before the fallback is even considered, and it ends in a raw
  `curl: (28) SSL connection timeout`. Probes now get one quick attempt (5 s
  connect, 10 s total, measured at 5 s in the same test); only the actual
  download stays patient. The step also names each source before trying it, so a
  pause is attributable rather than indistinguishable from a hang.

### Added

- **`--local <path>` installs a release directory or tarball already on the
  machine, with no network at all.** Every other path depends on reaching a URL,
  and on a filtered path they can fail together: the host times out, the GitHub
  API does not answer, and a source build then wants a Go toolchain from a third
  host. The files themselves travel fine by any other route. They are verified
  against the release's own SHA256SUMS exactly as a download would be — a
  tampered file is refused, a directory that is not a release is refused, and a
  release built for another architecture says so.

- **`scripts/publish-github-release.sh`** publishes a built release to GitHub
  Releases, with the changelog section for that version as its notes. The
  installer's GitHub fallback is only worth having if GitHub carries the current
  release; with the newest tag months behind the sources, an install that cannot
  reach the host falls all the way through to a source build instead.

## [2.8.3] — 2026-08-13

### Changed

- **A rejected handshake that matches nothing known now prints its opening
  bytes.** Two very different things reach that branch and their content cannot
  separate them, because one of them is deliberately shapeless: the stealth
  transport opens with 48 uniformly random bytes precisely so a scan finds
  nothing to fingerprint, and a peer set to it dialing a plain-tcp listener looks
  exactly like a bot probing the port. The bytes tell them apart by eye — a
  scanner repeats a recognisable string, a stealth peer never sends the same
  bytes twice.

- **A source that keeps failing the handshake is logged once per five minutes,
  with the number of attempts it stood in for.** A public tunnel port is found by
  scanners within hours, and one retrying every few seconds writes thousands of
  identical lines a day, burying everything that matters — including the line the
  operator is actually looking for. Every rejection is still counted in the
  engine's statistics; only the repeated line is collapsed. The count is the
  point: a scanner and a peer stuck in a reconnect loop read the same in one line
  and quite differently at "1 since" versus "312 since". Distinct sources stay
  independent, and the table that tracks them is bounded so a scan from many
  addresses cannot grow it.

## [2.8.2] — 2026-08-13

### Fixed

- **The WireGuard VPN's Foreign half created no tunnel at all**, so the pair
  could never connect. It set up WireGuard, wrote the client files, printed
  instructions — and never created the tunnel that dials the Iran server. The
  Iran side creates only its own half and then listens, so the result was the
  worst shape a failure can take: both servers reporting a tunnel that is up,
  the VPN port forwarded, and not one client able to connect.

  The Foreign half now asks for the tunnel port and creates its matching
  `role = "kharej"` tunnel in the same run, delivering to the WireGuard it just
  started on loopback. Verified by driving both halves and checking the pair
  that comes out: opposite roles, one tunnel port.

- **A refused handshake now says which of the three causes it was.** "not an
  emergency-tunnel peer (bad magic/version)" was the same line whether the other
  server runs a different core version, is configured for a different transport,
  or is not your server at all but a scanner off the internet — three problems
  with three unrelated fixes. The first bytes of the rejected hello tell them
  apart, so the log now names the peer's protocol version when it is a version
  mismatch, says the transports differ when a TLS or WebSocket peer arrives on a
  plain port, and keeps the old wording only for traffic that is genuinely not
  ours.

### Changed

- The Iran half of the WireGuard VPN now states outright that it is one half of
  a pair, that it will report itself running and carry nothing until the Foreign
  half exists, and prints the three numbers that half needs.

- The console's checks gained two that would have caught the above: the Foreign
  half is driven to completion like every other builder, and the two halves are
  driven together and required to come out as a connectable pair — opposite
  roles, matching tunnel port. Both fail on the previous release's console and
  pass on this one.

## [2.8.1] — 2026-08-13

### Fixed

- **The WireGuard VPN insisted both servers use the same port, which is wrong.**
  The Foreign server's WireGuard listen port is a purely local detail: nothing
  outside reaches it, because the tunnel delivers to it. Demanding it match the
  port users connect to on the Iran server meant that anyone already running
  WireGuard on the Foreign server hit a collision — asked for a port, told it
  was in use, with no way forward that made sense.

  The two are now separate. The Foreign side asks only for its own listen port,
  says plainly that it is local and need not match anything, and defaults to one
  that is actually free. It then prints both numbers the Iran side needs. The
  Iran side asks for the port users connect to and the port to deliver to,
  defaulting to the same, and writes a mapped forward when they differ.

  Verified end to end: `udp/51820` on the entry delivered to `udp/51999` on the
  exit, WireGuard-shaped datagrams intact, 2,670 sustained at 0.00% loss
  (p50 0.60 ms, p99 0.90 ms) — and the generated client file dials the Iran
  server on the public port while the server config listens on its own.

## [2.8.0] — 2026-08-12

### Added

- **Gaming → WireGuard VPN.** The existing WireGuard entry built a
  point-to-point link between the two servers — useful as a private path, but
  not a VPN anyone can connect to. That is now option 3, and option 2 is the one
  people actually want:

  ```
  client ──WireGuard/UDP──▶ Iran:<port> ──this tunnel──▶ Foreign ──▶ internet
  ```

  The VPN server runs only on the Foreign side, because that is where traffic
  should leave. The Iran server runs no WireGuard at all — it forwards the port.
  So a client's file names the Iran server and never learns the Foreign address,
  which is the whole point of the arrangement.

  On the Foreign server it generates the server key, the interface, and as many
  client files as asked for, each with its own key and address; writes the
  forwarding and NAT rules needed for clients to reach the internet, derived
  from the interface the default route actually uses; and starts it. On the Iran
  server it creates a tunnel that forwards the VPN's UDP port, tagged
  low-latency so it is scheduled ahead of bulk traffic.

  **Client MTU is 1280, not WireGuard's usual 1420.** Those packets travel
  inside this tunnel as well, so 1420 no longer fits; left at the default the
  VPN connects, small things work, and any real download stalls — a failure that
  reads as filtering and is not.

  This depends on the tunnel forwarding UDP, which is why it arrives now:
  WireGuard has no TCP mode to fall back to.

### Verified

The generated configuration is checked, not assumed: `wg-quick` parses both
files, the public key in every client file is the one derived from the server's
private key, and every client's key is registered as a peer on the server.

The carrying half was measured on the exact forward the console writes
(`udp/51820@ll`): WireGuard-shaped datagrams — a 148-byte handshake initiation,
92-byte keepalives, full 1280-byte data packets — all echoed back intact, and a
sustained run of 2,705 datagrams at **0.00% loss, p50 0.56 ms, p99 0.84 ms**.

WireGuard itself could not be run here: this environment has no kernel module
and no userspace implementation, so a live interface is untested. The
configuration and the transport it depends on are both verified.

## [2.7.2] — 2026-08-12

### Fixed

- **A prompt could spin at full CPU instead of stopping.** Type something a
  prompt rejects — a name with punctuation, a port out of range — and then close
  stdin (Ctrl-D, or a session that drops), and the retry loop re-asked forever
  against a stream that would never answer. The escape was a signal sent from
  inside a command substitution, which does not reliably reach the loop; every
  prompt now also learns from the read itself that stdin is gone, and returns.

  Found by driving the console's own menus rather than reading them, which is
  also how the checks below came about.

### Changed

- **The console's checks now run the menus, not just parse them.** Verifying
  that a builder exists and is reachable cannot show whether it *works*: a
  prompt that spins, or a builder that exits before writing anything, passes
  both and still leaves a user staring at a menu that does nothing.

  `check-panel.sh` now drives each Backpack builder to completion with scripted
  answers and requires the config it writes to be one the core accepts, and it
  reproduces the spin above and requires it not to happen. Both new checks were
  confirmed to fail on the previous release and pass on this one. The release
  build refuses to package a console that fails any of them.

## [2.7.1] — 2026-08-12

### Fixed

- **Backpack options 1–4 did nothing in 2.7.0.** Adding the OpenVPN entry
  replaced a span of the console that happened to contain four other builders,
  deleting Stealth, WSS, QUIC and UDP+FEC outright. Picking any of them called a
  function that no longer existed, so the screen returned to the menu with
  nothing having happened. All four are restored verbatim from 2.6.0.

- **A release can no longer be packaged with a broken console.** This class of
  bug is invisible to every check that existed: the shell is syntactically
  perfect, `bash -n` passes, the Go tests pass, and the fault only appears when
  a person picks that menu entry. `scripts/check-panel.sh` now verifies that
  every menu action resolves to a defined function, that no builder is
  orphaned, and that every config key the console writes is one the core
  actually parses. The release build refuses to package if it fails, and it was
  confirmed to catch precisely the deletion above.

### Removed

- **The OpenVPN engine.** It was not good enough, and carrying a half-solved
  thing is worse than not carrying it. `engine = "openvpn"`, `openvpn_port` and
  the Backpack entry are gone.

  UDP port forwarding stays — that is general (WireGuard, game servers, voice)
  and independently tested.

### Verified after the removal

Every protocol the console offers, end to end: Basic TCP 6395 · WS 4185 ·
TCPMUX 1877 · WSMUX 1451 · UDP 357, Backpack WSS 1635 · Stealth 1452 · QUIC
1112, TUN TCP 2027 · UDP 1056 · ICMP 548, SPF ICMP 554 · TCP 623 Mbit/s.

## [2.7.0] — 2026-08-12

A data plane built for one job: carrying OpenVPN over TCP.

### Added

- **`engine = "openvpn"` — a dedicated tunnel, not a port forward.**
  Backpack → 6 now builds it. Three things make it different from forwarding a
  port through the general engine, and each addresses a specific way the old
  arrangement failed:

  **Small relay buffers (16 KiB, against the general engine's 64).** This is the
  central decision. OpenVPN/TCP inside a TCP carrier is two reliable layers
  stacked, and what breaks them is not encryption — it is buffering. Every byte
  held in the middle is delay the *inner* connection measures as round-trip
  time, so its congestion control believes the path is fatter and slower than it
  is, overshoots, and stalls for seconds. It looks fine on a quiet link and
  falls apart when a real page loads. A big buffer benchmarks better and behaves
  worse; the buffer here is sized so the inner connection's timers keep
  describing the real path, and a test enforces that it stays small.

  **One carrier connection per VPN connection.** No multiplexer, so no shared
  window and no shared write queue: a bulk download cannot add delay to the
  VPN's control channel, and no stream can hold up a neighbour. The VPN's
  traffic can only ever be delayed by itself.

  **Carriers opened before they are needed.** The Foreign server keeps warm,
  authenticated carriers parked at the Iran server, so a connecting client finds
  the handshake already done — two or three round trips removed from every
  connect, on the long path this exists for. A client that arrives with none
  ready is refused in two seconds rather than left hanging, because OpenVPN's
  own retry is faster and cleaner than any wait.

  The port is asked once and is the same number on both servers: clients connect
  to it on the Iran side, the Foreign side dials it locally. Nothing to keep in
  step by hand.

### Measured

Two-namespace bed, one VPN connection and then forty at once:

| carrier | connect round trip (p50/p95) | one connection | 40 at once |
|---|---|---|---|
| Stealth | 0.34 / 0.60 ms | 1312 Mbit/s | 40/40 |
| WSS | 0.57 / 1.32 ms | 1972 Mbit/s | 40/40 |
| TCP | 0.25 / 0.47 ms | 3578 Mbit/s | 40/40 |

Those round trips include establishing a fresh VPN connection each time, which
is what the warm pool buys.

A 50-second soak with continuous churn — one steady session while others connect
and disconnect throughout: 4,631 probes with **0 failures** (p50 0.51 ms, p99
1.26 ms) alongside 5,784 completed connections, **0 refused**, both processes
alive, no panics. Pushed to ~850 connects/second the engine still carried 28,232
with 0 refused; the failures at that rate are the listen backlog, far past what
any OpenVPN deployment produces.

As always this is a loopback: it proves the data path, the lifecycle and the
absence of leaks, not what a real path will do.

## [2.6.0] — 2026-08-12

### Fixed

- **The UDP read loop could stall for seconds while the carrier reconnected.**
  Opening a stream waits for a live session, and that wait runs to four seconds
  while the tunnel is down. It happened inside the socket read loop, so a
  carrier hiccup stopped the forwarded port being read for exactly that long —
  every client's traffic discarded by the kernel meanwhile, which a VPN reads as
  the path vanishing.

  The session is now created immediately and its queue absorbs datagrams while
  the stream is established off the loop; if it never is, the session is dropped
  and its buffers released. The loop never blocks on anything now.

  Stated honestly: this is a real defect and the right fix, but it could not be
  shown to cause the reported symptom — eight simultaneous VPN users through two
  deliberate carrier breaks behaved identically before and after (worst blackout
  3.0 s in both, exactly the length of the break, full recovery).

### Added

- **The UDP forward now reports what it did**, in the stats endpoint and at the
  top of the health check: datagrams in and back, sessions opened, sessions that
  never got a carrier stream, and datagrams shed — split into queue-full and
  arrived-too-late.

  A VPN that stops working leaves no trace in bytes moved, so until now the only
  way to tell a drop from a stall from a crash was to guess, and guessing sent
  people changing carriers that were never at fault. Shedding above 5% is called
  out directly, because that much loss is what makes OpenVPN renegotiate and
  then give up.

### What was tested and did not reproduce

The reported failure — a VPN dying the moment a media-heavy app opens — was
chased with: 360 parallel connections in six waves (all fine, tunnel usable
after), a hard bidirectional burst of 37,750 datagrams (survived, 5/5 probes
after), a VPN session alongside four saturating downloads (0.0% loss, no gaps),
two carrier breaks mid-session (recovered fully), and the whole suite under the
race detector. None reproduced it.

That leaves the crash fixed in 2.5.2 as the only mechanism found that produces
exactly this symptom, and it needs both traffic and a session ending — which is
what a burst causes. If it recurs on 2.6.0, the health check now says which of
the three it is.

## [2.5.3] — 2026-08-12

Makes a crashing tunnel say so, and hardens the UDP session lifecycle.

### Added

- **Restarts are now visible.** A crashing tunnel and a filtered one look
  identical from the user's end — traffic stops, maybe comes back, stops again —
  and nothing here distinguished them. So a crash got diagnosed as filtering,
  which sends people changing carriers that were never at fault. The dashboard
  now marks any tunnel whose process has restarted, and the health check leads
  with it, names systemd's stop reason, and gives the journalctl line that shows
  why.

### Changed

- **The UDP session lifecycle is covered by a contention test.** 50 rounds of
  eight concurrent producers against a draining pump with teardown arriving from
  two other goroutines, run under `-race`. This is the shape that produced the
  2.5.2 crash — a burst coinciding with a session ending — and it now has a test
  that reproduces the conditions rather than the happy path.

## [2.5.2] — 2026-08-12

The UDP forwarding in 2.5.0/2.5.1 could crash the whole process. Fixed.

### Fixed

- **A tunnel carrying UDP could die outright and not come back.** Tearing a UDP
  session down closed the queue the socket read loop was still writing to, and a
  send on a closed channel panics — so the process died, taking every other
  tunnel on that server with it. systemd restarted it and the next teardown
  killed it again.

  It needed traffic *and* a session ending, which is why it looked like the
  tunnel worked, passed some data, then dropped completely and never
  reconnected. The trigger is ordinary: an idle client reaped, a stream error,
  or the carrier reconnecting — which closes every stream at once and so ends
  every UDP session at once, while datagrams are still arriving.

  A session now ends by signalling, and the queue is never closed. Proven both
  ways: the old teardown fails the new test with `send on closed channel`, the
  new one passes it, and the suite runs clean under `-race`. A churn test — 300
  short-lived clients created and destroyed while traffic flows — completes
  300/300 with the process alive and no panics.

- **QUIC now says why it could not connect.** The library reports a handshake
  that gets no answer as "no recent network activity", which sends people
  looking for a fault that is not there. Since this transport is the only UDP
  one, the message now names the causes in order: udp/port not open on both
  servers (a rule for tcp alone is the usual reason), or a network that blocks
  QUIC/HTTP-3 specifically even where TCP works — in which case Stealth or WSS
  are the carriers to use, because they are TCP.

  Worth stating plainly: QUIC was tested here over a 40-second idle session and
  a full data transfer and behaved correctly, so a QUIC that never connects is
  the path, not the build.

## [2.5.1] — 2026-08-12

The UDP forwarding added in 2.5.0 had a flaw that showed up exactly where a VPN
lives: under load.

### Fixed

- **One busy client stalled every client on the port.** A mux stream blocks its
  writer once the peer's window is full, and datagrams were written to it
  straight from the socket read loop. So the moment the carrier congested, the
  loop stopped reading — every other client on that forwarded port stalled
  behind whichever one was blocked, and the kernel's receive queue overflowed
  and discarded the backlog. A VPN under real traffic is precisely when the
  carrier congests, so this was reachable in normal use.

  Each client now has its own bounded queue and its own writer. Accepting a
  datagram never blocks: when the queue is full the newest is dropped, which is
  what the UDP path being replaced would have done anyway, and what OpenVPN is
  built to tolerate. The same fix applies to the return direction on the exit,
  where a stall is what a user feels as a stalled download.

- **Stale datagrams are dropped instead of delivered late.** A queued datagram
  past ~100 ms is worthless: the inner transport has already decided it was lost
  and sent another, so delivering it adds a duplicate and helps nobody. Dropping
  it is the same reasoning the TUN scheduler applies to its express class.

- **The exit no longer asks for the OpenVPN port.** It was never used — the port
  travels with every stream the entry opens, so the exit already knows where to
  deliver each one. Asking again only created a second place for the two servers
  to disagree.

### Added

- **A named diagnosis for oversized datagrams.** A forwarded datagram travels
  inside the carrier, which adds its own headers, so a VPN left at the default
  1500-byte MTU produces packets the outer path must fragment — and one lost
  fragment loses the whole datagram. Small packets keep working while large
  transfers stall, which reads as detection and is not. The tunnel now says so
  once, with the setting that fixes it.

### Measured

A sustained OpenVPN-shaped session over Stealth, with a bulk transfer saturating
the same tunnel — the case that used to stall:

| | datagrams | loss | rtt p50 / p99 | longest silence |
|---|---|---|---|---|
| idle carrier | 10,920 | 0.00% | 0.59 / 1.04 ms | 0 s |
| carrier saturated | 6,979 | 0.00% | 1.52 / 9.07 ms | 0 s |

Latency rises under load, as it must; nothing stalls and nothing is lost.

### Still true, and worth saying

Over Stealth or WSS the datagrams ride a *reliable* stream, so a lost carrier
segment still holds up that client's later datagrams until TCP resends it. The
queue and the stale-drop bound what this project can do about it; removing it
entirely needs an unreliable carrier, which is what QUIC's datagram extension
provides and this build does not yet use. On a path that loses packets, QUIC is
the carrier to choose for a VPN.

## [2.5.0] — 2026-08-12

Forwards carry UDP, and Backpack gains an OpenVPN option built on it.

### Added

- **UDP port forwarding through the mux engine.** It forwarded TCP and nothing
  else, which quietly decided what could be tunnelled: OpenVPN, WireGuard, game
  servers and voice are all UDP by preference, and anyone who wanted them
  through a Backpack transport had to fall back to the protocol's TCP mode.

  Every forward is now served on both protocols, matching what the firewall
  layer has always planned for the L3 engines. Each client of a forwarded UDP
  port gets its own mux stream, datagrams are length-framed so their boundaries
  survive an ordered byte stream, and idle clients are reaped after five minutes
  — long enough that a laptop which sleeps keeps its session rather than
  renegotiating.

- **Backpack → 6) OpenVPN.** Carries an OpenVPN server on the Foreign side over
  Stealth, QUIC or WSS. It allocates its own name, tunnel port and health port,
  so several can run side by side without colliding, and it prints the OpenVPN
  settings that matter on the exit — `proto udp`, `tun-mtu 1400`, `mssfix 1360`.

### Why sessions were dying

Worth stating plainly, because it changes what to configure. A carrier here
never exposes OpenVPN's fingerprint: OpenVPN's bytes travel inside this tunnel's
own AEAD, so an observer sees the carrier's shape and never the protocol's. A
session that survives minutes and then dies for good is almost never a detector.

It is TCP-over-TCP. Until this release the console could forward TCP only, so an
OpenVPN tunnel had to run `proto tcp`, and OpenVPN/TCP inside a TCP carrier
recovers every lost packet twice: OpenVPN's timer fires while the carrier is
still retransmitting, each copy adds load, and the two feed each other until the
session collapses and does not recover. It holds under light traffic and dies
under real use — the reported symptom exactly. Carrying the datagrams as
datagrams removes the inner reliability layer, leaving the user's own TCP as the
only thing recovering losses, which is the layer that should be.

MTU is the other half. OpenVPN's packets now travel inside the tunnel, so a
1500-byte one no longer fits; left at the default, large transfers blackhole
while small ones keep working, which also reads as detection and is not.

### Measured

A sustained OpenVPN-shaped session — 1200-byte datagrams, continuous, both
directions — over each carrier:

| carrier | datagrams | loss | rtt p50 / p99 | longest silence | reconnects |
|---|---|---|---|---|---|
| Stealth | 22,333 | 0.00% | 0.55 / 0.97 ms | 0 s | 0 |
| QUIC | 21,010 | 0.00% | 0.71 / 1.15 ms | 0 s | 0 |
| WSS | 16,493 | 0.00% | 0.57 / 1.00 ms | 0 s | 0 |

Datagrams of 1 to 65,000 bytes were echoed back byte-identical over every
transport, and TCP forwarding is unchanged (mux/tcp 1943, mux/stealth 1973
Mbit/s). As always this is a loopback: it proves the framing, the session
handling and the absence of drift, not what a real path will do.

### Not done, and why

The request listed packet-timing variation, random padding and traffic shaping.
Those are not implemented. Each one costs throughput or latency — the things
ranked first in the same request — and none of them would have addressed the
cause of these drops, which is not what the traffic looks like. The Stealth
carrier already pads inside its AEAD and has no wire constants to match; QUIC
and WSS already imitate protocols too common to block. If a real path shows
detection surviving all three carriers, that is the point to add shaping, with
the measurement to justify what it costs.

Automatic transport switching is also not implemented: switching carriers
mid-session drops every client on it, so it needs evidence that a carrier is
being blocked rather than the path being briefly bad, and this environment
cannot produce either.

## [2.4.2] — 2026-08-12

Both SPF profiles were unusable. Every protocol the console offers has now been
run end to end and carries traffic.

### Fixed

- **SPF never connected, on either profile: the listener was never given a
  peer.** SPF is the one carrier whose *listening* side also needs the other
  server's address — its packets carry a forged source, so nothing that arrives
  says where the peer really is, and a reply has nowhere to go. The console only
  ever asked the dialing side. The resulting config passed validation, the
  service started, and the carrier then refused its first packet. It asks both
  sides now, and validation rejects the missing peer up front with a message
  that explains why instead of letting it fail at runtime.

- **SPF icmp carried no traffic even once connected — the same kernel mirror
  that broke TUN/ICMP.** A listener's kernel answers echo requests by itself,
  and its reply repeats our payload with our echo id, which was everything this
  codec matched on. The dialer accepted that mirror as peer traffic and fed its
  own ciphertext to the handshake. The profile appeared to work only with
  `net.ipv4.icmp_echo_ignore_all=1`, which also stops the server answering ping
  on every interface. It now carries the same one-byte direction tag the TUN
  carrier uses; the wire format lives in one file shared by both, so a fix to
  one can no longer miss the other. Verified carrying 623 Mbit/s while the
  server still answers ordinary ping normally.

- **SPF tcp needed a firewall rule the operator had to add by hand.** That
  profile puts the link inside bare TCP segments no socket is listening for, so
  the kernel answers each with a reset and the carrier dies immediately. The
  console printed an iptables command and trusted people to run it on both
  servers — anyone who did not got a tunnel that handshaked forever. The tunnel
  installs the rule itself now, scoped to the tunnel port and the reset flag,
  tagged like every other rule it owns so it is removed on stop.

### Measured

Every protocol the console offers, run end to end on the two-namespace bed and
required to carry real bytes (resource/balance profile, CPU-bound loopback):

| | Mbit/s | | Mbit/s |
|---|---|---|---|
| Basic TCP (direct) | 6790 | TUN TCP | 2062 |
| Basic TCPMUX | 2058 | TUN UDP | 1179 |
| Basic WS (direct) | 1638 | TUN ICMP | 705 |
| Basic WSMUX | 1861 | SPF ICMP | 623 |
| Backpack WSS | 1687 | SPF TCP | 641 |
| Backpack Stealth | 1471 | Backpack QUIC | 1253 |
| Basic/Backpack UDP | 354 | | |

BIP could not be exercised here — this environment refuses an ICMPv6 raw socket
(`address family not supported`), which is a property of the container, not of
the carrier. Its framing is covered by the byte-for-byte test against the
library, and it shares every other code path with the ICMP carrier.

## [2.4.1] — 2026-08-11

A dead path was taking 20 seconds to notice. It now takes 5.

### Fixed

- **The heartbeat defaults were unreachable, so every tunnel ever built used the
  slow ones.** Both engines carry their own failover timings, and neither was
  ever applied: the config layer filled in 10 s between beats and 25 s of
  silence before a link was declared dead, and a non-zero value is exactly what
  "the operator chose this" looks like to an engine. The console even shipped a
  migration that strips the pinned 10/25 out of older configs so the faster
  default would take over — and it restored them to the very same 25 s.

  This matters most on the datagram carriers. A stream carrier does not wait for
  the heartbeat at all: TCP reports a broken path and the link is redialed in a
  fraction of a second. UDP, ICMP and BIP get no such error — silence is the only
  signal there is — so the timeout *is* their detection, and on the TUN engine
  every flow the kernel hashed to that queue goes nowhere until it fires.

  The defaults now live in one place, shared by both engines, and are reached.
  They are also shorter: four missed beats is what makes detection robust
  against jitter, and four is unchanged — only the period is, from 3 s to 2 s, so
  the wait is 8 s instead of 12. A heartbeat is a couple of bytes and only
  travels on a link with nothing else to say.

  Measured on a path broken and then restored, time until traffic flowed again:

  | carrier | before | after |
  |---|---|---|
  | TUN UDP | 20.1 s | **5.0 s** |
  | TUN ICMP | 20.1 s | **5.0 s** |
  | TUN TCP | 0.3 s | 0.2 s |

  Checked for the opposite failure too: no false disconnects on any carrier
  under sustained saturation, and none on a tunnel left idle for 45 s.

  Existing tunnels pick this up automatically — the console's migration finally
  does what it always said it did. `heartbeat_interval` and `heartbeat_timeout`
  still override it for a path that needs something else.

- **Saved configs no longer get a meaningless `heartbeat_interval = 0`.** The
  writer emitted the pair unconditionally; it now writes them only when they
  were actually set, which is how the 25 s got frozen into every config to begin
  with.

## [2.4.0] — 2026-08-11

A new transport, one protocol that turns out never to have worked, and the
socket tuning that every obfuscated protocol was silently missing.

### Added

- **QUIC transport (Backpack → QUIC).** Every other stream transport rides on
  TCP, where a single lost packet stalls everything behind it until the resend
  arrives, and the loss is read as congestion even when the link was merely
  flaky — the behaviour that turns a fast international route into a slow
  tunnel. QUIC carries independent streams over one UDP flow: a loss holds up
  only its own stream and recovery is a modern loss detector rather than a
  duplicate-ACK rule. The engine's several links become several streams on one
  connection, so there is one congestion controller that sees the whole path
  and one 4-tuple on the wire. It handshakes with TLS 1.3 and announces the
  ALPN HTTP/3 uses, so it reads as a browser talking to a modern website.
  **It is UDP** — the tunnel port must be open for UDP on both servers.

### Fixed

- **The reliable-UDP transport carried no data at all.** Its SYN was handled as
  stream data, so it took sequence number 0 on the receiver and moved the
  expected number to 1; the first real segment, whose number is also 0 because
  senders start there, was then rejected as already seen — and acknowledged
  anyway, so it was never resent. Every connection established, was accepted,
  and then carried nothing: the tunnel handshake timed out on one side and read
  EOF on the other. This affected the Basic UDP tunnel and Backpack's UDP+FEC.

  Nothing caught it because the package tested its ARQ and FEC against
  simulated links and never dialed its own transport. That round trip now
  exists, together with a test in the shape the engine really uses — several
  sessions over one listener socket.

- **Socket tuning never reached ws, wss or stealth.** The tuner asked for a raw
  TCP connection and quietly did nothing when it got a wrapper, which is what
  every obfuscated transport returns. The costliest part is TCP_NODELAY:
  without it Nagle's algorithm holds a small write back until the previous
  segment is acknowledged, so on exactly the protocols people choose when the
  path is hostile, an interactive packet could wait a round trip before it was
  even sent. They also lost BBR, the bufferbloat guard, and the keepalive that
  makes a dead link fail fast. The tuner now unwraps to the socket underneath,
  and the test reads the setting back off it rather than trusting the call.

### Performance

- **Reliable UDP is roughly seven times faster.** Its ARQ was driven only by an
  interval timer, which made the tick period the effective round trip in both
  directions: an acknowledgement waited for a tick before being sent, and the
  window it re-opened waited another before being used. Arrivals now drive it —
  ACK clocking, as TCP has always done. Dead-link detection had to stop counting
  fast retransmits to suit: a fast retransmit is caused by acknowledgements
  arriving, which is proof the path is alive; only a timeout means it is not.
  Measured end to end, bytes actually delivered: resource 39 → 225, balance
  54 → 291, fast 78 → 436 Mbit/s.

- **No allocation per packet on any carrier's listener.** The UDP carrier
  formatted the peer address into a string for every datagram's flow key and
  allocated an address per read; the ICMP carrier built its key with Sprintf;
  the SPF codec marshalled and parsed each packet through a library. All now use
  comparable keys and caller-owned buffers, with the ICMP wire format shared in
  one file rather than duplicated. The zero is asserted directly, because a
  correctness test cannot see an allocation.

### Measured

On a two-namespace bed at the resource profile — a CPU-bound loopback, so these
compare protocols against each other and do not predict a real path:

| protocol | before | after |
|---|---|---|
| Backpack QUIC | — | 907 |
| Basic/Backpack UDP | 39 | 272 |
| TUN ICMP | 438 | 686 |
| Basic TCP · WS · WSS · Stealth | — | 1580 · 1544 · 1233 · 1069 |

Idle tunnel ping is 0.5 ms over a 0.07 ms baseline with no loss on every TUN
carrier. Saturating the tunnel raises it to 1.7–3.7 ms with 0–2.5% loss on the
ping itself, the TCP carrier being the worst; that is a tunnel being driven past
its capacity on purpose, and this environment cannot reproduce a real path's
delay or loss to tell how much of it would remain there.

## [2.3.1] — 2026-08-11

The ICMP/BIP carrier gets the socket sizing and the per-packet budget the other
datagram carriers already had. Wire format is unchanged — a 2.3.1 end
interoperates with a 2.3.0 end — so either side may upgrade on its own.

### Changed

- **Datagram carriers now size their receive queue to absorb bursts.** Both the
  send and receive socket buffers were set to the same profile number; the
  receive side is now several times larger while the send side stays small. A
  tunnel's traffic arrives in bursts, and a burst larger than the receive queue
  is dropped by the kernel before the process sees it — loss the tunnel inflicts
  on itself, on the very carriers chosen because the path is already hard. An
  over-large receive queue costs only memory and adds no delay; an over-large
  *send* queue would add standing delay, so it is left small and queueing stays
  in the tunnel's own CoDel-managed scheduler. (fast 4/8 MiB, balance 1/4 MiB,
  resource 256 KiB / 2 MiB send/recv.)

- **The ICMP/BIP carrier sizes its socket buffers.** It set neither, so it alone
  ran on the kernel default of a couple hundred KiB and dropped bursts the UDP
  and SPF carriers absorbed.

### Performance

- **The ICMP/BIP hot path no longer allocates per packet.** Every send built its
  echo through `icmp.Message.Marshal`, every receive parsed through
  `icmp.ParseMessage`, and each read allocated a fresh buffer — tens of thousands
  of allocations a second at line rate, and on a one-core VPS that is CPU that
  could have moved bytes. Sends now write the fixed eight-byte echo header into a
  reused buffer, receives parse those eight bytes directly, and the read buffer
  is owned by the connection. The framing is asserted byte-for-byte against the
  library it replaced, for both ICMPv4 and ICMPv6. On a CPU-bound loopback bed
  the ICMP carrier rose from ~440 to ~625 Mbit/s; the real-path effect is the
  bursts the larger receive queue no longer drops.

## [2.3.0] — 2026-08-11

Throughput, in the two places a fixed number was standing in for the path.

### Changed

- **The mux receive window now auto-tunes.** It was fixed per performance
  profile, chosen from how much RAM the server has — but the window caps a
  single stream at window/RTT no matter what the link carries. The small-server
  profile's 512 KiB over a 100 ms route is 42 Mbit/s. Downloads hide that by
  spreading over many streams; one upload does not, which is why upload felt far
  worse than download on the same tunnel.

  A stream that turns over its whole window inside 500 ms is window-limited by
  definition, so its window doubles, up to 8× its initial size and never past
  the per-stream buffer guard. Growth is also bounded across the session, so
  many streams together cannot walk past the ceiling that protects this host's
  RAM, and a closed stream returns its share. A stream that drains a window
  slowly is left alone: that is the path being the limit, and growing would only
  add buffering.

- **TCP carriers leave SO_RCVBUF to the kernel.** Pinning it disables
  `tcp_moderate_rcvbuf`, after which the receive window can never exceed what
  was pinned — the resource profile pinned 256 KiB, a 21 Mbit/s ceiling per link
  over a 100 ms route, landing on whichever direction flows *into* that server.
  The send buffer was already left to autotuning for the mirror-image reason;
  now both are. An explicit `so_rcvbuf` still pins it. Datagram carriers are
  unchanged — UDP has no autotuning and still needs a real size.

### Measured

An existing test already showed the window is the binding constraint at only
10 ms of RTT: 512 KiB window = 103 MiB/s, 4 MiB window = 252 MiB/s, a 2.5x gap
that widens as latency grows.

The socket-buffer change cannot be demonstrated here: this environment has no
`sch_netem`, so the only available path is loopback, where the bandwidth-delay
product is ~zero and no BDP fix can show. Three runs of a single-stream TUN/TCP
transfer came out at 1476/1789/1622 Mbit/s against 1692 before — the same within
noise, which establishes no regression and nothing more. The gain exists only
where latency does, and belongs on a real route.

## [2.2.2] — 2026-08-11

### Fixed

- **TUN/ICMP and SPF crashed on the first connection.** 2.0.5 moved peer
  handshakes off the accept path by giving each listener a queue, added to the
  four constructors by hand — and two were missed. `AcceptLink` then dereferenced
  a nil queue, the process died with SIGSEGV, systemd restarted it, and the
  tunnel crash-looped until systemd gave up. Both carriers have been unusable
  since 2.0.5.

  The queue is now created where it is first used rather than in each
  constructor, so there is nothing left to forget. A test builds every listener
  as a zero value — exactly the "constructor forgot" case — and requires that
  accepting still works; the tests that shipped with the bug exercised the queue
  directly and never the listeners, which is why all of them passed.

  Verified end to end on a two-namespace testbed: all three TUN carriers now
  carry traffic at 0% loss with no panic in the logs.

## [2.2.1] — 2026-08-11

### Fixed

- **The console kept running its old self after updating itself.** `et` → Update
  replaces the script on disk, but a shell runs the script it was started with:
  the process stayed on the old version, so the header showed the old panel
  number and the menus were the old menus — a newly added section simply was not
  there — while the core reported the new version, because that is read by
  running `et-core` afresh each time. It reads exactly like a broken update, and
  the only thing needed was to leave the console and start it again. It now
  re-execs itself once the update succeeds, and the version-mismatch warning
  names that as the first thing to try.

## [2.2.0] — 2026-08-11

### Added

- **WSS transport** (`transport = "wss"`): the WebSocket framing over TLS,
  dialled with a real Chrome fingerprint via uTLS rather than Go's. A
  ClientHello is one of the few parts of a TLS connection an observer reads in
  full, and Go's is distinctive on its own — measured, Go sends 253 bytes where
  the Chrome fingerprint sends 563. A self-signed certificate is generated when
  none is configured; `tls_cert`/`tls_key`/`tls_sni`/`tls_verify` use a real one.
  The TLS is camouflage, not the security boundary — the tunnel's own handshake
  still authenticates and encrypts everything inside it.
- **Decoy site.** The WebSocket listener answered 404 to a wrong path and 400 to
  anything that was not an upgrade. Both are tells: a real site has a homepage,
  and a complaint about an upgrade announces that something here speaks
  WebSocket. Every request that is not a genuine tunnel connection now gets an
  ordinary nginx welcome page, 200, with a `Server: nginx` header.
- Backpack section now offers Stealth, WSS and the coded UDP carrier.

### Verified

Across two namespaces, for both new carriers: a user reaches the far service
through the tunnel, while a probe on the tunnel port gets nothing at all
(Stealth) or an nginx welcome page over TLS (WSS). Unit tests cover the decoy
across five kinds of probe, the ClientHello difference, and — for every new
listener — that a connection which says nothing does not delay a real peer.

## [2.1.0] — 2026-08-11

A fifth section, **Backpack**, and the fix for a whole class of silent
misconfiguration found while building it.

### Added

- **Stealth transport** (`transport = "stealth"`). Our core handshake opens with
  the constant bytes `45 54 02 03 03` at offset zero of every connection, and any
  peer that reached the port completed the exchange — so a scanner could both
  recognise the tunnel and confirm it. Stealth removes both: an ephemeral X25519
  exchange where each message is a public key plus a MAC keyed on a shared token,
  with no header, version or constant anywhere, and the MAC checked before
  anything is sent back. A peer without the token gets silence. The ordinary
  tunnel runs inside, so the constant that used to be on the wire is now within
  an encrypted stream where nothing can match it. Records carry random filler
  with the length under the AEAD, because padding an observer can read and
  subtract is not padding.

  Verified end to end across two namespaces: a user reaches the far service
  through the tunnel, while a scanner connecting to the tunnel port gets nothing
  at all and times out. Tests assert no byte position is constant across 24
  handshakes, that a wrong token draws no reply, that identical payloads produce
  varying record lengths, and that a silent peer does not delay a real one.

- **Backpack section in the console**, offering Stealth and the coded UDP
  carrier, with the token generated for you and the honest note that error
  correction has not yet paid for itself on this build.

### Fixed

- **The console wrote settings the core silently ignored.** The loader ended in
  "ignore unknown keys", so any option without a matching case was dropped
  without a word: the tunnel came up, looked correct, and simply did not have the
  behaviour that was asked for. `ws_path`, `ws_host` and `low_latency` — the
  Gaming section's entire latency mode — had been written and ignored for
  releases. All are now read; unknown keys are collected and reported, `et-core
  validate` fails on them so the console cannot write one, and a running tunnel
  warns rather than being stopped. A test walks the schema so a new field cannot
  be added without wiring it up.
- `tunnel_count` printed `0` twice when no tunnels existed (`grep -c` prints its
  zero *and* fails), so every section offered a default name like `bp0\n0`.
- The reliable-UDP ARQ now accounts for the parity the FEC layer adds when
  sizing its congestion window. Without it the encoder put 30% more packets on a
  path the window had already measured, displacing the data the parity existed to
  protect.

## [Unreleased]

### Added

- **Forward error correction for the reliable-UDP carrier** (`fec_data` /
  `fec_parity`, both ends must match). Every `fec_data` packets carry
  `fec_parity` Reed-Solomon parity packets; any `fec_data` of the group rebuild
  it, so an isolated loss is repaired from packets already in flight instead of
  costing a round trip. Segments below 128 bytes bypass the code — a pure
  acknowledgement sharing a group with full-sized data makes the parity almost
  entirely padding, which measured worse than the retransmissions it saved.

  **Off by default, and it should stay off until the note below is resolved.**

### Measured, and not yet worth enabling

Across 1/3/8/15% loss over a 100ms round trip, coded throughput came out at
0.43x, 0.82x, 0.90x and 0.32x of the plain carrier — never a win.

The likely cause is that parity is generated below the congestion control that
paces the connection: the ARQ sizes its window against what the path will carry,
and the encoder then adds 30% more packets to that path without telling it. At a
bottleneck those displace the data they were meant to protect. Fixing it means
accounting for parity inside the congestion window, which is a change to the
ARQ rather than to the codec.

The test harness — a userspace relay with a timer per packet — also caps
throughput well below what the carrier reaches on a clean socket, so the
absolute numbers understate everything and the comparison is suggestive rather
than conclusive. Enough to keep the feature off; not enough to call it useless.

## [2.0.5] — 2026-08-10

### Fixed

- **A port scanner could hold a TUN tunnel down.** The L3 engine ran each peer's
  handshake on the accept path itself, so a connection that opened the tunnel
  port and then said nothing was charged to every real link queued behind it —
  the full handshake timeout, serially, per silent connection. The listening side
  is a public address, so this is not a rare event.

  Measured on a two-namespace testbed, time until the tunnel established its
  first link: no silent connections 0.5s, one 9.6s, three 29.7s. After the fix it
  is 0.5s with ten of them held open.

  Each handshake now runs in its own goroutine and only finished links reach the
  accept loop, with a ceiling on how many can be in flight so a flood is shed
  rather than queued. Applies to all four TUN carriers. The mux and direct
  engines already did this correctly and are unchanged.

## [2.0.4] — 2026-08-10

### Fixed

- **BIP with an IPv4 peer retried forever.** BIP carries the link inside ICMPv6,
  so the address it dials has to be IPv6. Given an IPv4 one the resolver answered
  "no suitable address found" — wording that reads like a DNS or routing fault
  and sends you to the firewall — and every queue repeated it every five seconds
  with no way to tell what was actually wrong.

  Three changes, at the three points where it was knowable: the config is
  rejected at validation time with the reason and the fix; the runtime dial error
  now says the peer has no IPv6 address and that `tun_mode=icmp` is the IPv4
  equivalent; and the console asks for an IPv6 peer when BIP is chosen, warns
  when the server has no global IPv6 at all, and offers to switch method rather
  than writing a config that cannot connect.

## [2.0.3] — 2026-08-10

### Fixed

- **The ICMP carrier carried nothing and cycled every 25s.** A listener's kernel
  answers echo requests by itself, and its reply repeats the dialer's own payload
  with the same ICMP id — by address and id alone it cannot be told apart from a
  real reply. The dialer read its own ciphertext as peer traffic, no genuine
  frame was ever accepted, and both queues tore down on the liveness timeout.
  Each payload now carries a one-byte direction tag, so a mirrored request is
  recognised and dropped.

  This also removes the `net.ipv4.icmp_echo_ignore_all=1` requirement the carrier
  used to have. That sysctl did avoid the collision, but it silenced ping on
  every interface including the tunnel address — so the standard way to test a
  tunnel stopped working on exactly the servers that needed it.

  A side effect of the same tag: the listener now ignores ordinary ping traffic
  instead of opening a flow per source and offering each to the handshake.

  Verified on a two-namespace testbed with real ICMP sockets: with kernel replies
  enabled the tunnel went from 100% loss and both queues cycling at 25s, to 0%
  loss and no cycling over a 30s soak.

## [2.0.2] — 2026-08-10

### Fixed

- **A stale console next to a fresh core now fails the install instead of
  passing it.** Verification only checked that the panel ran, not which version
  it was, so an update that replaced `et-core` but left an old `et` in place
  reported success — and the server kept showing the pre-2.0 menus. The panel is
  now verified by version, `et` being shadowed earlier in `PATH` is reported, and
  the console itself warns in its header when panel and core come from different
  releases.
- **The console no longer spins forever when stdin closes.** Every prompt runs
  inside a command substitution, so the EOF handler's `exit` ended only that
  subshell; the menu redrew against a closed stdin at full CPU. EOF now signals
  the real shell and leaves cleanly.

## [2.0.1] — 2026-08-10

### Fixed

- **Updating actually updates.** The installer resolved a version only from the
  release host or GitHub Releases, so when the sources moved ahead of the last
  published release, `et` → Update reinstalled the old binary and nothing
  appeared to change. It now compares whichever release it found against the
  `VERSION` file on the default branch and builds from source when the branch is
  newer. An unreleased fix reaches the server through the normal update path.
- `--from-source` stamped the core version as `dev` instead of reading the
  cloned tree's `VERSION`, so a source install under-reported itself and the
  post-install verification warned about a version mismatch.
- Added `--source source` for an explicit source build, and kept the update URL
  pointing at the release host when a host install falls through to a source
  build.

## [2.0.0] — 2026-08-10

Version 2. The create-tunnel flow is four categories, and every protocol listed
under them now exists in the core.

### The four sections

| Section | Protocols | Backed by |
|---------|-----------|-----------|
| **Basic** | TCPMUX · TCP · WSMUX · WS · UDP | mux/direct engine over the tcp, ws and reliable-udp transports |
| **TUN** | TCP · UDP · ICMP · BIP | the L3 engine's four carriers |
| **Gaming** | UDP tunnel · WireGuard | latency-tuned L3-over-UDP, and kernel WireGuard |
| **SPF** | ICMP · TCP | raw-socket spoofed carriers |

### Added
- **Non-multiplexed engine (`engine = "direct"`)**, so Basic's TCP and WS are
  genuinely distinct from TCPMUX and WSMUX rather than aliases. One tunnel
  connection carries one user connection. It is slower than the multiplexed
  engine — a new connection costs a handshake instead of a frame — and it is the
  right pick when a per-connection traffic shape matters more than that, or when
  a handful of long-lived flows would gain nothing from a second multiplexing
  layer. The exit parks a pool of pre-authenticated connections at the entry, so
  a user still pays no handshake at connect time.
- **WireGuard in the Gaming section.** The kernel implementation is driven
  rather than reimplemented: nothing in userspace matches it per packet. The
  panel generates the keypair, allocates a conflict-free subnet, port and
  interface, writes `/etc/wireguard/wgN.conf` with a 25 s keepalive and MTU
  1420, prints the public key for the other server, and starts
  `wg-quick@wgN` once the peer key is in. `wireguard-tools` is installed
  automatically where a package manager is available.

### Changed
- Basic offers all five protocols; the section header explains what
  multiplexing buys and costs so the choice is informed rather than arbitrary.
- Gaming tunnels now set `low_latency = true`, which the reliable-UDP ARQ reads
  to shorten its timers, shallow its windows and back off more gently.
- `et-core validate` resolves the transport for the direct engine too.

### Verified
Eight tunnels created back to back through the wizard — TCPMUX, TCP, WSMUX, WS,
UDP, TUN/ICMP, TUN/BIP, Gaming/UDP — all valid, with unique ports (1234-1241),
unique subnets (10.10.10/20/30) and unique interfaces (et0-et2). Full Go suite
green including the ARQ's loss-recovery and the direct engine's wire format.

### Still not implemented
- **SPF BIP.** SPF offers `icmp` and `tcp`. Spoofing an IPv6 source is not the
  same problem as IPv4: `IP_HDRINCL` has no IPv6 equivalent that lets a raw
  socket set the source address, so it needs `IPV6_PKTINFO` and the kernel still
  validates the address against the interface. That is a different mechanism
  from the existing IPv4 path, not an extra case in it.
- High-traffic and long-term stability runs, which need two real servers on a
  real path rather than a namespace pair.

### Compatibility
Existing configurations are untouched and keep working; the console migrates
pre-2.0 pinned values in place on first run.

## [1.14.0] — 2026-08-10

Reliable UDP in the core, so the Basic section's UDP protocol is real rather
than absent.

### Added
- **Reliable UDP transport (`transport = "udp"`).** UDP alone gives no
  ordering, no retransmission and no congestion control, and the crypto and mux
  layers both require a reliable byte stream. Rather than weakening those, this
  supplies the guarantees underneath them — a selective-repeat ARQ with:
  cumulative `una` plus an explicit ACK list (one loss does not stall everything
  behind it), Jacobson/Karels RTT estimation driving the RTO, fast retransmit
  after 3 later ACKs, TCP-style slow start and congestion avoidance, and flow
  control against the peer's advertised window. Presented as a `net.Conn`, so
  every layer above it is unchanged.
  Unit-tested for in-order delivery, complete recovery at 5/15/30% packet loss,
  congestion-window growth, peer-window enforcement, and dead-path detection.
- `low_latency` config option: switches the ARQ to shorter timers, shallower
  windows and gentler backoff. The Gaming section sets it.
- Basic → UDP in the console.

### Fixed
- **The reliable-UDP `Write` had no backpressure.** It accepted data at memory
  speed while the wire moved at cwnd per round trip, so half a gigabyte piled up
  in three seconds, overflowed the UDP socket buffer, and the resulting loss
  collapsed the congestion window — a tunnel that reported 1481 Mbit/s while
  actually carrying 8. The send queue is now bounded and `Write` blocks, which
  is the backpressure the mux above expects. Real throughput measured
  106 Mbit/s on loopback with the queue bounded at ~5 MB.
- Slow start never ran: `ssthresh` started at 2, dropping straight into
  congestion avoidance, which opens the window about one segment per RTT.

### Performance note
The reliable-UDP carrier is slower than raw TCP on a fast path (106 Mbit/s vs
~1600 on loopback) — a userspace ARQ pays a syscall and a scheduler hop per
segment where the kernel does not. That is the expected trade, and the reason to
choose it is a path that throttles or blocks long-lived TCP, not raw speed on a
path where TCP already works.

### Still missing from the requested design
- **WireGuard** is not implemented. Integrating it properly means driving the
  kernel's WireGuard (key management, `wg`/netlink, interface and peer setup) —
  a self-contained piece of work that did not fit alongside the ARQ.
- **SPF BIP** (spoofed ICMPv6) is not implemented; SPF still offers `icmp` and
  `tcp`.
- **Basic → plain TCP** (one socket per user connection, unmultiplexed) is not
  offered, because the multiplexed carrier is strictly better on the same wire.

### Compatibility
Wire protocol unchanged for existing transports. Configurations are untouched.

## [1.13.0] — 2026-08-10

A new WebSocket transport, and a ground-up rewrite of the installer and the `et`
console around four protocol sections.

### Added
- **WebSocket transport (`transport = "ws"`).** The link opens with an ordinary
  HTTP/1.1 Upgrade and then carries binary WebSocket frames, so it traverses
  CDNs and reverse proxies (Cloudflare, nginx, Caddy) and survives middleboxes
  that reject unrecognised TCP payloads. Client frames are masked per RFC 6455,
  control frames are handled, and a request to the wrong `ws_path` gets a plain
  404 so a probe sees an ordinary web server. Measured 1606 Mbit/s end to end.
  New options: `ws_path`, `ws_host`.
- **`et` v2.0 — a rewritten console** organised in four sections:
  **Basic** (TCPMUX, WSMUX), **TUN** (TCP/UDP/ICMP/BIP), **Gaming**
  (latency-first UDP), **SPF** (ICMP/TCP). Plus a live dashboard with CPU,
  memory and per-tunnel link/RTT, statistics from the core's `/stats`, health
  checks that ping the peer and report loss, and `--list/--status/--migrate/--tune`
  for scripting.
- **An optimiser that derives every performance parameter from the machine.**
  Cipher follows AES-NI (`aes-256-gcm` with, `chacha20-poly1305` without —
  roughly a 3× difference either way), the memory profile follows RAM, link
  count follows core count, and MTU follows the carrier (1400 on a stream
  carrier, 1320 where a datagram must leave header room). A fresh install needs
  no hand-tuning.
- **Host tuning is applied, not just advised**: BBR, `fq`, `tcp_rmem`/`tcp_wmem`
  ceilings, `tcp_slow_start_after_idle=0` and friends are written to
  `/etc/sysctl.d/99-emergency-tunnel.conf` (delete the file to revert).
- **Conflict-free multi-tunnel allocation.** Ports, health ports, `10.10.N.0/24`
  subnets and interface names are all allocated from what is actually free, so
  six tunnels created back to back never collide.

### Fixed
- **`et-core validate` accepted a transport the binary does not carry.** It is
  the `ExecStartPre` gate, so a config naming an unbuilt transport passed
  validation and then crash-looped the service with a much less obvious error.
- **The old panel leaked its role menu into the configuration.** `role_prompt`
  printed to stdout while being captured with `$(...)`, so the menu text landed
  inside `role = "…"` and the generated config was invalid. (Found by testing
  the wizard end to end; the rewrite prints prompts to stderr.)
- **The console span forever on stdin EOF.** A closed pipe made every menu read
  return its default in a tight loop. EOF now exits cleanly.
- **The installer aborted where `systemctl` exists but is not running**
  (containers, chroots, image builds) because `set -e` caught the failure.

### Improved
- Installer resolves releases from the release host with an automatic fallback
  to GitHub, installs binaries via a temporary name and rename (a half-written
  download can never replace a working binary), reports what it preserved, and
  runs migration plus a restart of running tunnels on upgrade.
- Migration removes values older panels pinned into every config — the 10s/25s
  heartbeats, `so_sndbuf`, `channel_size = 1024` — all of which now block better
  core defaults. Identity (name, ports, subnet, interface) is never touched and
  the original is kept in `/usr/local/lib/emergency-tunnel/state`.

### Not included
- **Basic/UDP and Gaming/WireGuard are not offered**, because the core has no
  UDP transport (it needs a reliability layer) and no WireGuard implementation.
  Menu entries that generate configs the core cannot run would be worse than
  their absence. The Gaming section is a real latency-first tuning of the UDP
  **TUN** carrier, not a separate protocol.
- **SPF has no BIP profile** — SPF supports `icmp` and `tcp` only.

### Compatibility
Wire protocol unchanged (v3). Existing configurations keep working; the console
migrates them in place on first run and on upgrade.

## [1.12.0] — 2026-08-10

Audit and upgrade of the **TCP Reverse (`mux`)** protocol, which 1.11.0 left
largely untouched while the TUN data plane was rebuilt. It is the default and
recommended engine, and it had the same class of problem the TUN path did:
an unbounded, strictly first-come-first-served egress queue.

### Fixed
- **Data race in session selection.** `sessionSet.pick()` advanced its
  round-robin cursor while holding only a *read* lock, so every concurrent user
  connection on the entry side raced on it — confirmed by the race detector, and
  the entry side calls it once per connection. The cursor is now atomic, and a
  regression test drives it from 16 goroutines. Symptoms would have been uneven
  session selection; under Go's memory model it was undefined behaviour.
- **No session-wide receive bound.** Per-stream flow control bounds a
  conformant peer and the per-stream ceiling bounds one misbehaving stream, but
  neither bounded the product — a peer ignoring flow control across hundreds of
  streams could drive the host out of memory. The session now tracks total
  buffered receive bytes and tears down a peer that exceeds the ceiling.

### Improved — the mux egress scheduler
The writer's two channels (256 control frames + 1024 data frames) could hold
~16 MB of DATA, which on a 20 Mbit link is six seconds of standing queue. Being
channels, they were also strictly FIFO, so one bulk stream's backlog sat in
front of every other stream's data. Both are replaced by a real scheduler:

- **Byte-bounded egress (256 KiB).** Past the budget `Stream.Write` blocks,
  which stops draining the user's socket and pushes back via TCP. Backpressure,
  not dropping, is the right answer for a reliable stream — the opposite of the
  L3 path, where the kernel hands us packets regardless and CoDel must drop.
- **Per-stream round-robin.** N active streams each get ~1/N of the link rather
  than whoever queued first taking all of it. Streams from `@ll` forwards keep
  their own higher-priority rotation.
- **Coalesced, lossless window updates.** Credit is accumulated per stream
  instead of queued as individual frames, so a burst of small reads cannot flood
  the control class and — the point — a window update can never be dropped for
  lack of queue space. Losing one does not cause a hiccup, it strands the peer's
  sender forever.
- **FIN is ordered with its stream's data**, not treated as a control frame.
  A test drives 1 MiB followed by an immediate `Close()`; routing FIN through
  the control class loses 20% of the payload, so this is enforced by test rather
  than by convention.
- **Adaptive write batching.** The writer's coalescing limit now follows the
  link's measured drain rate (the same `netq.Budget` the TUN engine uses, moved
  to a shared package) instead of a fixed 32 KiB, so a batch never blocks the
  wire long enough to delay the control frames the peer is waiting on.
- **`/stats` gains `queued_bytes` and `peak_queued_bytes`.**

### Verified
End-to-end on a two-namespace testbed with real TUN devices and sockets:

| | 1.11.0 | 1.12.0 |
|---|---|---|
| mux session RTT under load (shaped 20 Mbit) | 209 ms | 153-179 ms |
| mux peak egress backlog | up to ~16 MB | 256 KiB (bounded) |
| mux bulk, unshaped | 1579 Mbit/s | 1701-1749 Mbit/s |
| mux new-stream setup under load | 0.5 ms avg | 0.4-0.5 ms avg |
| TUN tcp carrier, unshaped | — | 1859 Mbit/s, ping 0.68 ms |
| TUN udp carrier, unshaped | — | 1160 Mbit/s, ping 0.52 ms |

New-stream setup was already fast in 1.11.0 (SYN was always prioritised); the
gains here are in the queue's depth, its fairness between streams, and the
session's own round trip under load.

### Compatibility
Wire protocol unchanged from 1.11.0 (still v3) — a 1.11.0 peer interoperates
with a 1.12.0 peer. Config schema, defaults and CLI unchanged.

## [1.11.0] — 2026-08-10

A networking-layer overhaul aimed squarely at the two symptoms that made the
tunnel feel unreliable: **latency spikes under load** and **poor throughput**.

> **Upgrade both servers.** The link protocol is now v3 and a v2 peer cannot
> talk to a v3 peer. The mismatch surfaces as a clean handshake rejection
> ("not an emergency-tunnel peer (bad magic/version)"), not as corrupt data, but
> the tunnel will not come up until both ends run 1.11.0.

### The latency problem

A ping that sat at ~97 ms and jumped to ~400 ms whenever traffic flowed was not
path jitter — it was queueing. The transmit path was a plain 256-packet FIFO
(~350 KB), so on a 20 Mbit link every packet, interactive or not, waited behind
up to ~140 ms of bulk backlog. Three more unmanaged queues sat behind it: the
kernel's socket send queue, the TUN device's `txqueuelen`, and (on the `fast`
profile) a pinned 4 MiB `SO_SNDBUF`.

### Added
- **Two-class packet scheduler** (`internal/l3/sched.go`). Latency-critical
  traffic — ICMP/ICMPv6, TCP segments with no payload (pure ACK, SYN, RST), UDP
  ≤ 192 B (DNS, QUIC ACKs, VoIP, game traffic), anything ≤ 128 B — is drained
  ahead of bulk data, so a ping never waits behind a download. The split is
  conservative about reordering: only traffic where overtaking is provably
  harmless is expedited, and a TCP **FIN is never expedited** because it consumes
  sequence space and would truncate the stream. Expediting pure ACKs also keeps
  the inner connection's ACK clock steady, which raises throughput.
- **CoDel AQM (RFC 8289)** on the bulk class. Drops start only when queue
  sojourn time stays above 5 ms for a full 100 ms interval, giving inner TCP the
  congestion signal it needs to settle at a rate that keeps the queue short —
  full throughput without the standing delay.
- **`TCP_NOTSENT_LOWAT`** (128 KiB) on every carrier socket. Without it the
  kernel accepts megabytes of application data on a congested path, putting it
  beyond the reach of the scheduler; a packet marked latency-critical would still
  sit behind whatever bulk data the kernel took a moment earlier.
- **`fq_codel` and a short `txqueuelen`** on the TUN device, for per-flow
  fairness on the way in — one download can no longer add delay to an
  interactive session sharing the tunnel.
- **Real link RTT measurement.** Control frames carry a timestamp and are echoed
  by the peer; the smoothed round trip is exposed as `rtt_ms` on `/stats`.
  Comparing it against a ping through the tunnel says immediately whether extra
  latency is the path or queueing.
- **Anti-replay window** (1024 counters) on the datagram carriers, so duplicated
  or replayed packets are rejected instead of re-injected into the TUN device,
  while ordinary path reordering is still accepted.
- **Startup host-tuning advice.** The core checks `tcp_congestion_control`,
  `default_qdisc`, `tcp_rmem`/`tcp_wmem` ceilings and
  `tcp_slow_start_after_idle`, and logs a specific fix for anything working
  against it.
- **Adaptive frame budget.** A frame is indivisible on the wire, so its size is
  a hard floor on how long an express packet can be delayed — at 20 Mbit a
  60 KiB frame is 24 ms of head-of-line blocking, enough to negate the priority
  scheduler completely. The batch size is now derived from the link's measured
  drain rate so one frame never occupies the wire for more than ~4 ms, while a
  link that never blocks keeps full-size frames and their amortised syscall cost.
  On a shaped 20 Mbit link under 2× unresponsive UDP load, this moved ping
  through the tunnel from 75.5/115.7/158.4 ms (min/avg/max, fixed 60 KiB) to
  3.3/15.5/44.5 ms.
- **Richer `/stats`**: `rtt_ms`, `express_packets`, `bulk_packets`,
  `tx_dropped`, `queue_depth`, `bad_frames`.

### Improved
- **One syscall per frame.** The AEAD layer wrote the 2-byte length prefix and
  the ciphertext as two separate `write` calls, which with `TCP_NODELAY` put a
  2-byte TCP segment in front of *every* frame. Both are now sealed into one
  buffer and written once.
- **Frames carry up to 63 KiB** (was 16 KiB). A 60 KiB packet batch is now one
  frame, one seal and one syscall instead of four frames and eight writes.
- **The L3 engine dropped its redundant framing.** One packet batch maps onto one
  AEAD frame, so the extra 4-byte header and the `io.ReadFull` reassembly loop
  are gone, and frames are read without copying out of the decryption buffer.
- **Zero-allocation data path.** The TUN reader used to allocate a right-sized
  slice for every packet despite having a buffer pool; packets now stay in their
  pooled buffer from read to frame. The UDP/ICMP/SPF demultiplexers pool their
  buffers too. `BenchmarkQueuePushPop` and `BenchmarkWriteFrame` report
  0 allocs/op.
- **Batching is opportunistic instead of timer-driven.** The fixed 2 ms flush
  timer added up to 2 ms to every packet on an idle tunnel; the batch is now
  flushed the moment the queue drains, so light load pays nothing and heavy load
  still fills whole frames.
- **Faster failover.** Heartbeat defaults moved from 10 s/25 s to 3 s/12 s (for
  both the TUN and mux engines), liveness is checked at millisecond rather than
  second resolution, `TCP_USER_TIMEOUT` dropped to 12 s, and reconnect backoff
  now starts at 250 ms and caps at 5 s. Packets still queued when a link dies are
  discarded rather than delivered late after the reconnect.
- **The mux writer coalesces up to 32 KiB** (was 60 KiB) — one AEAD frame per
  write, and a bounded wait for a high-priority frame produced while the writer
  is pushing a batch.
- **A bad datagram no longer kills the carrier.** On an open UDP/ICMP port
  anyone can inject a packet; the link now skips undecryptable datagrams (and
  counts them) instead of tearing down, which closed a trivial remote
  denial-of-service. A sustained flood of them still fails the link, since that
  means the peer's keys genuinely do not match.

### Fixed
- A packet larger than the carrier's frame budget (reachable with an MTU
  configured above what the carrier can wrap) failed the write and cycled an
  otherwise healthy link. It is now shed and counted.

### Compatibility
Wire protocol v2 → v3: **both servers must be upgraded together.** Config schema,
defaults and CLI are unchanged apart from the heartbeat defaults; existing
configs keep working, and an explicit `heartbeat_interval`/`heartbeat_timeout`
still overrides them.

The panel no longer pins those two values into every generated config — doing so
froze new tunnels at the old 10 s/25 s and stopped tuned core defaults from ever
reaching them. Tunnels created before this release still carry the explicit
values; delete those two lines from `/etc/emergency-tunnel/<name>.toml` (or
recreate the tunnel) to pick up the faster defaults.

## [1.10.1] — 2026-07-22

Fixes TUN/SPF peer-IP validation, which rejected valid input and blocked
creating a tunnel on a server that has none while the peer already has several.

### Fixed
- **Peer tunnel IP no longer rejects a `/prefix`.** The previous prompt asks for
  CIDR (`This host's tunnel IP (CIDR)`), so typing `10.10.20.1/24` for the peer
  was the natural next step — but the check required a bare dotted-quad and
  refused it. A `/prefix` is now accepted and trimmed (the config schema needs a
  bare address, so this normalisation is required, not cosmetic).
- **The peer default is now derived from the address actually entered.** It used
  to be computed *before* the local IP was typed, from this host's free-subnet
  suggestion. On a server with no tunnels that suggestion is `10.10.10.x`, so
  overriding the local IP to `10.10.20.2/24` (to join a tunnel that already
  exists on the other server) left the peer default pointing at a different
  network — the reported failure. It now mirrors the entered address
  (`10.10.20.2/24` → `10.10.20.1`).
- **Subnet membership is actually validated.** The error message claimed "in the
  tunnel subnet" while the code only checked "is an IP" and "differs from ours".
  Real prefix-aware checking is now performed (any prefix length, not just /24),
  and each rejection says precisely what is wrong — bad address, same as this
  host, or outside the tunnel's subnet (which is named).

### Improved
- The TUN/SPF step states that the suggested subnet is merely what is free *on
  this server*, and that joining a tunnel the peer already has is done by
  entering that tunnel's subnet — with a worked example.
- After both addresses are accepted the wizard confirms the resulting network,
  e.g. `Tunnel network: 10.10.20.0/24 (this host 10.10.20.2, peer 10.10.20.1)`.

### Compatibility
Unchanged defaults, configs and wire protocol. Tunnel 1 still defaults to
`10.10.10.1/.2`; genuinely invalid input (wrong subnet, malformed address, same
address on both ends) is still rejected, by the wizard and the core.

## [1.10.0] — 2026-07-22

Multiple independent tunnels per server. Creating a second tunnel no longer
reuses the first one's ports, interface or subnet, and clashing configurations
are refused before they can fail at runtime.

### Added
- **Auto-allocated, non-conflicting defaults.** The wizard now asks the core for
  values that collide with nothing already on the host. The first tunnel on a
  server still gets the historical defaults exactly; each additional tunnel steps
  to the next free value:

  | Resource       | Tunnel 1        | Tunnel 2         | Tunnel 3         |
  |----------------|-----------------|------------------|------------------|
  | `tunnel_port`  | `1234`          | `1235`           | `1236`           |
  | `health_port`  | `9090`          | `9091`           | `9092`           |
  | `tun_iface`    | `emergency-tun` | `emergency-tun2` | `emergency-tun3` |
  | tunnel subnet  | `10.10.10.0/24` | `10.10.20.0/24`  | `10.10.30.0/24`  |
  | SPF spoof pair | `…4.29/…222.4`  | `…4.30/…222.5`   | `…4.31/…222.6`   |

- **Cross-tunnel conflict detection.** `FindConflicts` reports every host-global
  resource a new tunnel would take from an existing one, with an actionable
  message naming the other tunnel. Covered: `tunnel_port` (two listeners can't
  bind one; two dialers can't share peer+port), `health_port`, `tun_iface`,
  overlapping tunnel subnets, client-facing forward ports, and SPF `spoof_dst_ip`.
- **New commands:** `et-core suggest-defaults [--dir D] [--role R] [--format sh|json]`
  and `et-core check-conflicts --config F [--dir D]`.
- **Panel integration:** the wizard pre-fills the allocated values, states which
  ones must match on the peer server, and **refuses to start a conflicting
  tunnel** (config kept for editing). Status and edit views surface conflicts for
  tunnels that already overlapped.

### Why these specifically
- A duplicate `tun_iface` does **not** error — Linux attaches the second tunnel
  as another queue on the **same** TUN device, silently stealing its packets.
- Every SPF listener receives a copy of all matching raw packets and distinguishes
  tunnels only by the peer's spoofed source, so two SPF tunnels sharing
  `spoof_dst_ip` cross-talk. Distinct pairs isolate them with no wire change.

### Compatibility
- **No breaking changes.** Defaults on a fresh host, existing configs, and the
  on-the-wire protocol are unchanged — pinned by tests. Configs written by older
  versions load, validate and are correctly accounted for by the allocator.
- The conflict check runs at **creation** time, never from `ExecStartPre`, so an
  already-installed tunnel can never be blocked from starting by a pre-existing
  overlap.

## [1.9.0] — 2026-07-19

Fixes the "mux can't connect" report and the TUN ~10 s ping / ~50% loss, then
balances throughput and cuts latency across every protocol. Root-caused with a
multi-agent code audit (27 findings, adversarially verified).

### Fixed — mux "cannot connect"
The mux link path is byte-for-byte the same as tun(tcp), so a real link failure
was impossible where tun connected. The actual causes:
- **No "connected" log.** mux printed nothing on session establishment (tun
  prints `Tunnel connected successfully`), so a working tunnel looked dead in
  `journalctl`. It now logs `mux tunnel connected: session up …` on the 0→1
  session transition and `mux tunnel disconnected …` on 1→0, on both ends.
- **Silent forward-bind failure.** The Iran VPN/listen port is bound in-process;
  if it was busy, clients got connection-refused while sessions still showed up.
  `serveForward` now **retries with backoff** (self-heals a restart race) and
  surfaces `forwards_configured` / `forwards_up` in `/stats`.
- **Exit hard-dialed `127.0.0.1`.** If the Kharej service isn't on loopback,
  every stream failed. New **`exit_host`** config (default `127.0.0.1`) points
  the exit at the address the service actually binds.

### Fixed — TUN ~10 s latency / ~50% loss
- **Dead-queue blackhole.** The default `pool` was **8** while the panel/examples
  use **4**; the kernel fans TUN flows across all queues, so a mismatch left some
  queues with no peer link, silently dropping every flow hashed to them. Default
  is now **4** (matches everything), a **rate-limited error** fires when a peer
  opens more links than there are queues, and an optional **`tun_queues`** field
  decouples the count if needed. **Both servers must use the same value.**
- **Carrier bufferbloat (the 10 s ping).** The TCP carrier pinned `SO_SNDBUF` to
  1–4 MiB, a standing FIFO that buffers seconds of data under congestion and
  defeats priority scheduling. The carrier now uses **kernel send-buffer
  autotuning** (tracks BDP → no throughput loss, no standing queue). Scoped to
  the TCP carriers; datagram carriers are unchanged.
- **Shallower queues + drop-head.** Per-queue channel depth is now profile-based
  (fast 512 / balance 256 / resource 128, was a fixed 1024), and a full queue now
  **drops the oldest** packet and keeps the newest (freshest data, lower latency).

### Added — throughput balance & latency
- **`@ll` low-latency forward flag** (e.g. `443@ll`, combinable: `443@pp@ll`) —
  opens the user's mux streams **high-priority** in both directions, so gaming/
  interactive traffic isn't stuck behind bulk transfers. Flags now combine.
- **Datagram MTU guard.** SPF/udp/icmp carriers clamp the inner MTU to **1320**
  (with a warning) so a wrapped packet can't exceed a ~1400-byte path and
  blackhole. The tcp carrier keeps MTU 1380.
- **Mux receive-buffer ceiling** (16 MiB/stream) — defense-in-depth so a peer
  ignoring flow control can't grow memory without bound; the stream resets.
- **Removed the no-op one-shot `TCP_QUICKACK`** (it reverts after one segment on
  Linux; `TCP_NODELAY` is the real latency knob and stays). **Heartbeat
  validation** now compares *effective* values, so setting only the interval
  can't leave the timeout defaulted below it and cause false timeouts.

### Notes
- **Upgrade both servers together** (or set `pool` explicitly on both first): a
  1.8.x peer defaults `pool` to 8, so upgrading only one end creates the 4-vs-8
  mismatch this release warns about.
- The TUN/SPF data-plane fixes are analyzed + unit-tested here; validate latency/
  loss on a real Iran↔Kharej pair (iperf3 both directions + ping on the same
  queue). mux (the default) is verified end-to-end, including the reconnect path.

## [1.8.1] — 2026-07-11

Fixes the SPF/datagram long-run disconnect that required a manual Iran-side
restart, makes shutdown clean, and improves disconnect diagnostics.

### Fixed
- **Root cause of the SPF TCP multi-hour disconnect.** The datagram listeners
  (SPF, UDP, ICMP) serve every queue from a single shared raw socket, and any
  error from that socket's read — including a *transient* `ENOBUFS` (kernel
  receive buffer briefly overflowing under load, which the busier SPF **TCP**
  profile hits hardest) or `EINTR` — tore the whole socket down permanently.
  Every link was then stranded, producing endless "heartbeat timeout, cycling
  link" until the Iran (listener) service was restarted by hand. The listeners
  now distinguish transient read errors (skip the packet, keep serving) from
  real closure (stop), so a momentary overload no longer kills the tunnel.
- **Stalled reader could hang until link teardown.** The channel-backed flows
  captured their read deadline once at entry, so a deadline set *after* a read
  had already blocked (exactly what the pump does to cycle a dead link) never
  woke it — a reader could hang, holding its queue slot and starving reconnects.
  Read deadlines now interrupt an in-progress read (`deadlineGate`), matching
  real `net.Conn` semantics. This also removes the reliance on force-closing the
  link to unblock readers, so **shutdown/restart is clean** and no longer trips
  the "shutdown exceeded 3s — forcing exit" watchdog.
- **Dialer no longer cycles the link on a transient read error.** SPF and ICMP
  client reads skip `ENOBUFS`/`EINTR` instead of failing the link, cutting
  needless reconnect churn under load.

### Diagnostics
- Richer disconnect logging (no per-packet spam): heartbeat timeouts now read
  `SPF connection lost on queue N: heartbeat timeout after 27s of silence
  (limit 25s) — cycling link`, and reconnects log the attempt number and a
  `reconnected after N attempt(s)` on recovery.

### Notes
- The SPF raw-socket data path remains Linux + `CAP_NET_RAW` and is not
  runtime-verified in CI; the fixes are exercised through the UDP carrier, which
  shares the identical listener/flow/deadline code, plus unit tests for the
  transient-error classification and the deadline gate.

## [1.8.0] — 2026-07-10

Makes the VPN listen port an Iran-only concept, hardens long-running stability
with automatic recovery, and lifts single-stream throughput substantially.

### Changed
- **The VPN Listen Port is now Iran-only, for every engine.** The wizard asks for
  it only on the Iran (entry) server with the description "This is the VPN/service
  port that your VPN clients connect to. It is only required on the Iran server."
  The Foreign server is never asked for a listen port, forwarding, or NAT — it
  only carries the tunnel. Enforced at three layers: the panel doesn't prompt,
  `config.Validate` rejects `forwards` on a `kharej` config, and the firewall
  installs rules only when `role = iran`.

### Performance
- **Up to ~8.8× higher single-stream throughput (mux).** The per-stream receive
  window is now sized by performance profile — `fast` 4 MiB, `balance` 2 MiB,
  `resource` 512 KiB (was a fixed 512 KiB) — lifting the bandwidth-delay-product
  ceiling on long-distance links. Measured single-stream throughput at 10 ms RTT
  rose from ~42 MiB/s to ~373 MiB/s (see `BenchmarkWindowThroughput`).
- **WINDOW_UPDATE frames are now high-priority.** They previously queued behind
  bulk DATA, stalling the sender's credit and collapsing throughput under load
  (notably the lighter/upload direction). This evens out upload vs download.
- **MSS clamping for forwarded TCP.** Port-forward rules now add a
  `TCPMSS --clamp-mss-to-pmtu` mangle rule so large segments don't blackhole at
  the smaller tunnel MTU (the classic "connects but big transfers hang").
- Raw/UDP socket buffers and the SPF zero-alloc receive path from 1.7.0 are
  retained.

### Stability (fixed)
- **Automatic recovery from a wedged tunnel.** A new liveness watchdog exits the
  process (systemd then restarts it cleanly) if the tunnel was healthy and then
  stays down past a 120 s recovery window. It never fires before the tunnel has
  come up once, so an unreachable peer can't cause a restart loop. No more manual
  restarts after a long-run drop.
- **Faster reconnect after a network drop (TUN/SPF).** On heartbeat timeout or
  shutdown the link is now closed immediately, so a writer blocked on a dead
  socket unblocks at once instead of waiting out `TCP_USER_TIMEOUT` (~20 s → ~1 s
  reconnect). End-to-end reconnect verified: sessions drop to 0 on peer loss and
  return automatically with data intact.

## [1.7.0] — 2026-07-10

Adds kernel port forwarding for the TUN and SPF engines, confirms source-IP
spoofing on both SPF profiles, and applies an allocation/buffer pass to the
datagram data path.

### Added
- **Port forwarding for TUN and SPF.** A tunnel can now forward a VPN/service
  port across the tunnel to the peer. During creation the wizard asks for the
  port(s); the daemon installs the matching iptables rules when the interface
  comes up and removes them on stop, so a restart or reboot restores them (they
  are tied to the tunnel process) and a delete clears them. Each forward is
  applied for **both TCP and UDP** so it covers WireGuard, OpenVPN, game servers
  and streaming without the user picking a transport. Rules are:
  - `nat/PREROUTING` DNAT the listen port to `peer_tun_ip:<port>`,
  - `filter/FORWARD` ACCEPT the forward **and** its return (works even when the
    default FORWARD policy is DROP),
  - `nat/POSTROUTING` MASQUERADE out the tunnel interface so replies route back.

  Rules are idempotent (existing rules are swept by a per-tunnel comment tag
  before re-adding, so no duplicates) and validated (ports 1–65535, a required
  `peer_tun_ip` target). Config: reuses the existing `forwards = [...]` syntax
  (`443`, `443,8443`, `200-300`, `8000=9000`). New `et-core firewall-down
  --config <f>` subcommand and a `firewall.Plan`/`Apply`/`Remove` package. The
  panel enables and persists `net.ipv4.ip_forward` when a forwarding tunnel is
  created.

### Fixed
- **SPF TCP now spoofs the source IP** (confirming the 1.6.1 unification). Both
  the `icmp` and `tcp` SPF profiles send every frame through the raw-socket
  carrier with `spoof_src_ip` as the IP source and accept only packets from
  `spoof_dst_ip`. The panel's "TCP — no spoofing" wording is corrected.

### Performance
- **SPF receive path allocates nothing per packet.** `spfConn.Read` now reuses a
  single receive buffer (was a fresh allocation on every read) — measurably lower
  GC pressure and CPU on the SPF hot path.
- **Raw and UDP socket buffers follow the performance profile** (`SO_RCVBUF` /
  `SO_SNDBUF` sized from `fast`/`balance`/`resource`, best-effort), so
  high-throughput bursts aren't dropped by a small default kernel buffer.

### Notes
- Port forwarding is Linux-only (iptables/netfilter) and requires the daemon's
  `CAP_NET_ADMIN` (already granted by the unit). The rule-generation logic is
  unit-tested; the live iptables interaction should be validated on a real Linux
  host. Forwarding is a routed L3 relay to the peer's tunnel IP — the peer must
  have the service listening on that port.

## [1.6.1] — 2026-07-09

Bug-fix release for issues found testing 1.6.0: fast restart/delete, the SPF
setup wizard, and SPF source-IP spoofing on **both** carrier profiles.

### Fixed
- **Fast tunnel restart and delete.** Shutdown no longer waits on a blocked TUN
  read. The TUN fd is now opened non-blocking so the Go runtime poller can
  interrupt `Read` the instant the device is closed; the core adds a 3 s
  shutdown watchdog as a hard backstop, and the systemd unit sets
  `TimeoutStopSec=5s` + `KillMode=mixed`. Measured stop-to-exit is now well under
  a second (was up to systemd's 90 s default on a stuck read). Repeated
  create/restart/delete leaves no zombie processes, leaked FDs, or lingering
  goroutines.
- **SPF setup wizard now asks for the spoof IPs.** The panel was missing its
  `ask_ip` helper, so SPF creation silently skipped `spoof_src_ip` /
  `spoof_dst_ip` and then failed config validation. The wizard now prompts for
  both (validated IPv4, must differ) before writing the config.
- **SPF spoofing applies to the TCP profile too.** Previously only the ICMP
  profile spoofed the source IP; the TCP profile ran as an ordinary reliable
  link. Both profiles now share the same raw-socket spoof carrier — every SPF
  frame, ICMP or TCP, is sent with `spoof_src_ip` as its source and accepted
  only from `spoof_dst_ip`. The old non-spoofing SPF-TCP wrapper was removed.

### Added
- **Role-based SPF spoof defaults.** The wizard pre-fills Iran →
  `spoof_src_ip=195.62.4.29`, `spoof_dst_ip=5.34.222.4` and Foreign the reverse.
  Both remain editable and are format/pairing-validated.
- **SPF logging.** `SPF tunnel connected: <local> <-> <peer>` on link-up and
  `SPF spoof mapping initialized successfully: profile=… src=… dst=…` at carrier
  start. The panel prints `Tunnel restart completed successfully` and
  `Tunnel removed successfully`.

### Changed
- SPF codec logic (ICMP + TCP envelopes) split into a platform-neutral file with
  round-trip unit tests; the raw-socket send/receive stays Linux-only.

### Notes
- SPF spoofing is strictly a point-to-point tunnel between two servers you
  control — outgoing packets use your configured `spoof_src_ip`, inbound are
  accepted **only** from `spoof_dst_ip`. It is not an attack tool.
- SPF-TCP caveat unchanged: drop the kernel's RST for the unsolicited segments on
  both hosts — `iptables -A OUTPUT -p tcp --sport <tunnel_port> --tcp-flags RST
  RST -j DROP`. SPF remains Linux + `CAP_NET_RAW`, framing/validation tested but
  not runtime-verified in CI.

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
