#!/usr/bin/env bash
#
# Collect everything needed to diagnose a tunnel, in one pasteable report.
#
#   sudo bash <(curl -fsSL "https://raw.githubusercontent.com/AMirHossein-donyavii/tunnel/main/scripts/et-diag.sh?cb=$(date +%s)")
#
# Run it on BOTH servers during the fault and paste both outputs. A report from
# one side alone cannot tell "my peer sent nothing" from "my peer sent and it
# did not arrive", which is the distinction most faults come down to.
#
# Secrets are redacted: token, psk and any key material are replaced before
# anything is printed. Read the redact() function below if you want to check
# that before running it — you should.
set -uo pipefail

CONF_DIR="${CONF_DIR:-/etc/emergency-tunnel}"
LIB_DIR="${LIB_DIR:-/usr/lib/emergency-tunnel}"
SINCE="${SINCE:-15 min ago}"

h()  { printf '\n===== %s =====\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# redact removes anything that authenticates: the value is replaced outright,
# never abbreviated or hashed, because a prefix of a secret is still a secret.
# Two servers with different tokens is a real cause of "handshake fine, no
# data", but that is not worth printing either half of a key for — it shows up
# in the log as a handshake that fails, not one that succeeds.
redact() {
    sed -E \
        -e 's/^([[:space:]]*(token|psk|password|secret|private_key|tls_key)[[:space:]]*=[[:space:]]*").*(")/\1<redacted>\3/I' \
        -e 's/(PrivateKey|PresharedKey)[[:space:]]*=.*/\1 = <redacted>/I'
}

h "identity"
date -u '+%Y-%m-%dT%H:%M:%SZ  (UTC)'
uname -srm
[ -r /etc/os-release ] && . /etc/os-release && echo "$PRETTY_NAME"
echo "cores=$(nproc 2>/dev/null)  mem=$(awk '/MemTotal/{printf "%d MB", $2/1024}' /proc/meminfo 2>/dev/null)"

h "versions"
for b in "$LIB_DIR/et-core" /usr/local/bin/et-core /usr/bin/et-core; do
    [ -x "$b" ] && { echo "$b:"; "$b" version 2>&1 | sed 's/^/  /'; break; }
done
[ -f "$LIB_DIR/VERSION" ] && echo "installed VERSION file: $(cat "$LIB_DIR/VERSION")"
for p in "$LIB_DIR/et-panel.sh" /usr/local/bin/et; do
    [ -f "$p" ] && grep -m1 '^SCRIPT_VERSION=' "$p" | sed "s|^|$p: |"
done

h "tunnel configs (redacted)"
for f in "$CONF_DIR"/*.toml; do
    [ -f "$f" ] || continue
    echo "--- $f"
    redact < "$f"
done

h "units"
systemctl list-units 'emergency-tunnel@*' --all --no-legend --no-pager 2>/dev/null | sed 's/^[[:space:]]*[●*][[:space:]]*/  /'

h "how each tunnel started"
journalctl -u 'emergency-tunnel@*' --since "$SINCE" --no-pager 2>/dev/null \
    | grep -E 'tunnel starting|resources:|icmp:|host tuning' | tail -20

h "health lines (the per-minute summary)"
journalctl -u 'emergency-tunnel@*' --since "$SINCE" --no-pager 2>/dev/null \
    | grep -E 'last 1m' | tail -10

h "link cycling and errors"
journalctl -u 'emergency-tunnel@*' --since "$SINCE" --no-pager 2>/dev/null \
    | grep -iE 'cycling|reconnect|refused|mismatch|ERR|WRN' | tail -40

h "counts over the window"
journalctl -u 'emergency-tunnel@*' --since "$SINCE" --no-pager 2>/dev/null | awk '
    /cycling link/      {cyc++}
    /connected success/ {conn++}
    /reconnect/         {rec++}
    END {printf "  cycling=%d  reconnects=%d  connected=%d\n", cyc, rec, conn}'

h "tun interfaces"
# Names the engine gives its devices, not every interface whose name happens
# to contain "et" — eth0 is not a tunnel and its counters say nothing here.
tun_devs() { ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 \
                 | grep -E '^(tun|et)[0-9a-z_-]*$' | grep -vE '^eth'; }
ip -brief addr show 2>/dev/null | grep -E '^(tun|et)[0-9a-z_-]*[[:space:]]' | grep -vE '^eth' || echo "  none"
for d in $(tun_devs); do
    echo "--- $d"
    ip -s link show "$d" 2>/dev/null | tail -4
done

h "carrier sockets and listeners"
if have ss; then
    ss -lunp 2>/dev/null | grep -i et-core || echo "  no udp listeners"
    ss -ltnp 2>/dev/null | grep -i et-core || echo "  no tcp listeners"
    echo "raw sockets (icmp/ipip/gre carriers):"
    ss -w -p 2>/dev/null | grep -i et-core | head -8 || echo "  none"
fi

h "kernel settings that change tunnel behaviour"
for k in net.ipv4.tcp_congestion_control net.core.default_qdisc \
         net.ipv4.tcp_slow_start_after_idle net.core.rmem_max net.core.wmem_max \
         net.ipv4.icmp_echo_ignore_all net.ipv4.ping_group_range; do
    printf '  %s = %s\n' "$k" "$(sysctl -n "$k" 2>/dev/null || echo '?')"
done

h "firewall rules touching the tunnel"
if have nft; then nft list ruleset 2>/dev/null | grep -iE 'icmp|gre|ipip|drop|reject' | head -15; fi
if have iptables; then iptables -S 2>/dev/null | grep -iE 'icmp|DROP|REJECT|47|4 ' | head -15; fi

h "process"
ps -o pid,etime,pcpu,pmem,rss,args -C et-core 2>/dev/null | head -10

echo
echo "===== end. Run this on the OTHER server too and paste both. ====="
