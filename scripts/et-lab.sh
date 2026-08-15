#!/usr/bin/env bash
#
# A whole Iran<->Europe path, reproduced on one machine.
#
# This exists because "the tunnel is slow" and "the other one is faster" are
# unanswerable without a path you can hold still. Every claim about throughput
# in the changelog is produced by this script, and anyone can re-run it:
#
#   sudo scripts/et-lab.sh                       # 140 ms, no loss
#   sudo DELAY=70ms LOSS=0.005 scripts/et-lab.sh # 140 ms, 0.5% loss
#   sudo MBIT=100 PERFLOW=true scripts/et-lab.sh # each carrier link policed at 100
#   sudo MODE=icmp DELAY=0 scripts/et-lab.sh     # raw carrier speed, any encapsulation
#
# Layout:
#
#   ns et-kh  --veth--  ns et-wan  --veth--  ns et-ir
#   (kharej,             delay/loss/           (iran,
#    dials)              policer                listens)
#
# The relay is a userspace program rather than netem, because netem is not
# available in every container and because per-carrier-flow policing — the
# condition that decides single-stream speed on this route — is not something
# netem expresses. With DELAY=0 the relay is skipped entirely and the two halves
# are joined directly, which is the only way to run the raw-IP carriers (icmp,
# ipip, gre) since the relay forwards UDP.
#
# Needs root, /dev/net/tun, and iproute2. Nothing it does escapes its network
# namespaces, and everything is torn down on exit.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
CORE="${CORE:-$ROOT/et-core}"
WORK="${WORK:-/tmp/et-lab}"

DELAY="${DELAY:-70ms}"     # one-way; 140 ms RTT is the measured Iran<->Hetzner figure
LOSS="${LOSS:-0}"          # one-way loss probability
MBIT="${MBIT:-0}"          # one-way ceiling, 0 = unlimited
PERFLOW="${PERFLOW:-false}" # apply MBIT per carrier link instead of in total
MODE="${MODE:-udp}"        # carrier: udp | icmp | ipip | gre | tcp  (DELAY=0 for raw ones)
POOL="${POOL:-4}"
MTU="${MTU:-1320}"
PROFILE="${PROFILE:-fast}"
AQM="${AQM:-codel}"
STRIPE="${STRIPE:-packet}"
CC="${CC:-cubic}"
DUR="${DUR:-15s}"
FLOWS="${FLOWS:-1}"

ns() { ip netns exec "$1" "${@:2}"; }
die() { printf '%s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ]     || die "needs root (network namespaces)"
[ -x "$CORE" ]         || die "no core binary at $CORE — build it with: go build -o et-core ./cmd/et-core"
[ -c /dev/net/tun ]    || die "no /dev/net/tun"
command -v ip >/dev/null || die "iproute2 is not installed"

# The path simulator and the throughput pair are ordinary commands in this
# repository, built here so the lab needs nothing installed beyond Go.
mkdir -p "$WORK"
WAN="$WORK/et-lab-wan"; TP="$WORK/et-lab-tp"
if [ ! -x "$WAN" ] || [ ! -x "$TP" ]; then
    command -v go >/dev/null || die "need Go to build the lab tools (or pre-build them into $WORK)"
    (cd "$ROOT" && go build -o "$WAN" ./cmd/et-lab-wan && go build -o "$TP" ./cmd/et-lab-tp) \
        || die "could not build the lab tools"
fi

DIRECT=false
[ "$DELAY" = "0" ] && DIRECT=true

cleanup() {
    for n in et-ir et-kh et-wan; do ip netns del "$n" 2>/dev/null; done
}
trap cleanup EXIT
cleanup
mkdir -p "$WORK"

# ---- the path ---------------------------------------------------------------
if $DIRECT; then
    ip netns add et-ir; ip netns add et-kh
    ip link add etIR type veth peer name etKH
    ip link set etIR netns et-ir; ip link set etKH netns et-kh
    ns et-ir ip addr add 10.77.0.1/24 dev etIR; ns et-kh ip addr add 10.77.0.2/24 dev etKH
    ns et-ir ip link set etIR up; ns et-kh ip link set etKH up
    IR_LISTEN=10.77.0.1; KH_PEER=10.77.0.1; IR_EXTRA='peer = "10.77.0.2"'
else
    ip netns add et-ir; ip netns add et-kh; ip netns add et-wan
    ip link add etIR type veth peer name etIRw
    ip link add etKH type veth peer name etKHw
    ip link set etIR netns et-ir;  ip link set etIRw netns et-wan
    ip link set etKH netns et-kh;  ip link set etKHw netns et-wan
    ns et-ir  ip addr add 10.77.1.1/24 dev etIR
    ns et-wan ip addr add 10.77.1.2/24 dev etIRw
    ns et-kh  ip addr add 10.77.2.1/24 dev etKH
    ns et-wan ip addr add 10.77.2.2/24 dev etKHw
    ns et-ir ip link set etIR up; ns et-wan ip link set etIRw up
    ns et-kh ip link set etKH up; ns et-wan ip link set etKHw up
    IR_LISTEN=10.77.1.1; KH_PEER=10.77.2.2; IR_EXTRA=''
fi
for n in et-ir et-kh; do
    ns "$n" ip link set lo up
    # A 140 ms path needs an 8 MB window to fill at 500 Mbit; without this the
    # kernel's own receive buffer is the ceiling and every result is that limit.
    ns "$n" sysctl -qw net.ipv4.tcp_rmem="4096 262144 67108864" 2>/dev/null
    ns "$n" sysctl -qw net.ipv4.tcp_wmem="4096 262144 67108864" 2>/dev/null
    ns "$n" sysctl -qw net.ipv4.tcp_congestion_control="$CC" 2>/dev/null
done

# ---- the two halves ---------------------------------------------------------
common() { # common <role> <listen_ip-or-peer lines>
    cat <<EOF
role = "$1"
engine = "tun"
tun_mode = "$MODE"
tunnel_port = 9000
tun_iface = "etlab0"
mtu = $MTU
pool = $POOL
profile = "$PROFILE"
aqm = "$AQM"
stripe = "$STRIPE"
token = "et-lab"
log_level = "info"
EOF
}
{ echo 'name = "et-lab-ir"'; common iran
  echo "listen_ip = \"$IR_LISTEN\""; echo "$IR_EXTRA"
  echo 'tun_ip = "10.66.0.1/24"'; echo 'peer_tun_ip = "10.66.0.2"'
  echo 'health_port = 9091'; $DIRECT && echo 'interface = "etIR"'
} > "$WORK/iran.toml"
{ echo 'name = "et-lab-kh"'; common kharej
  echo "peer = \"$KH_PEER\""; $DIRECT && echo 'listen_ip = "10.77.0.2"'
  echo 'tun_ip = "10.66.0.2/24"'; echo 'peer_tun_ip = "10.66.0.1"'
  echo 'health_port = 9092'; $DIRECT && echo 'interface = "etKH"'
} > "$WORK/kharej.toml"

if ! $DIRECT; then
    ns et-wan "$WAN" -listen 10.77.2.2:9000 -upstream 10.77.1.1:9000 \
        -delay "$DELAY" -loss "$LOSS" -mbit "$MBIT" -perflow="$PERFLOW" \
        >"$WORK/wan.log" 2>&1 &
fi
ns et-ir "$CORE" run --config "$WORK/iran.toml"   >"$WORK/iran.log" 2>&1 &
sleep 0.5
ns et-kh "$CORE" run --config "$WORK/kharej.toml" >"$WORK/kharej.log" 2>&1 &

for _ in $(seq 1 40); do
    ns et-kh ping -c1 -W1 10.66.0.1 >/dev/null 2>&1 && break
    sleep 0.5
done
ns et-kh ping -c1 -W1 10.66.0.1 >/dev/null 2>&1 || {
    echo "the tunnel never came up:"; tail -n 15 "$WORK/iran.log" "$WORK/kharej.log"; exit 1; }

echo "carrier=$MODE stripe=$STRIPE aqm=$AQM pool=$POOL mtu=$MTU cc=$CC"
echo "path: delay=${DELAY} loss=${LOSS} ceiling=${MBIT}Mbit perflow=${PERFLOW}"
ns et-kh ping -c5 -i0.3 10.66.0.1 2>&1 | tail -1

# ---- the transfer -----------------------------------------------------------
ns et-ir "$TP" -listen 10.66.0.1:5001 >"$WORK/sink.log" 2>&1 &
sleep 0.3
rm -f "$WORK"/src.*
pids=""
for f in $(seq 1 "$FLOWS"); do
    ns et-kh "$TP" -connect 10.66.0.1:5001 -t "$DUR" >"$WORK/src.$f" 2>&1 &
    pids="$pids $!"
done
for p in $pids; do wait "$p"; done
sleep 1
grep -h '^sender:'   "$WORK"/src.* 2>/dev/null | sort
grep -h '^receiver:' "$WORK/sink.log" 2>/dev/null | sort
grep -icE "cycling|reconnect" "$WORK/iran.log" >/dev/null && \
    echo "link cycles: $(grep -cE 'cycling|reconnect' "$WORK/iran.log" "$WORK/kharej.log" | paste -sd' ')"
