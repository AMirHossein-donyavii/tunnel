#!/usr/bin/env bash
#
# Emergency Tunnel — management console.  Installed as /usr/local/bin/et
#
# Layout (single file by design: the installer downloads and checksums one
# script, so there is no partial-install state to reason about):
#
#   1. constants + UI primitives      6. optimiser (per-protocol defaults)
#   2. validation helpers             7. sections: Basic / TUN / Gaming / SPF / Backpack
#   3. system + network probes        8. tunnel management
#   4. tunnel registry + allocator    9. dashboard + diagnostics
#   5. config reader/writer          10. migration + main menu
#
set -uo pipefail

SCRIPT_VERSION="2.2.1"
CORE="/usr/local/bin/et-core"
PANEL="/usr/local/bin/et"
CONF_DIR="/etc/emergency-tunnel"
LOG_DIR="/var/log/emergency-tunnel"
LIB_DIR="/usr/local/lib/emergency-tunnel"
SVC_PREFIX="emergency-tunnel@"
STATE_DIR="${LIB_DIR}/state"

# ============================================================================
# 1. UI primitives
# ============================================================================
if [ -t 1 ]; then
    R=$'\033[0m'; B=$'\033[1m'; DIM=$'\033[2m'
    RED=$'\033[38;5;203m'; GRN=$'\033[38;5;114m'; YEL=$'\033[38;5;221m'
    BLU=$'\033[38;5;75m';  CYN=$'\033[38;5;80m';  MAG=$'\033[38;5;176m'
    GRY=$'\033[38;5;245m'
else
    R=''; B=''; DIM=''; RED=''; GRN=''; YEL=''; BLU=''; CYN=''; MAG=''; GRY=''
fi
W=74   # console width

# Leaving on EOF (see ask) is delivered as a signal, because the read happens
# inside a command substitution. Handle it as an ordinary quit.
trap 'printf "\n"; exit 0' TERM

have() { command -v "$1" >/dev/null 2>&1; }
rule() { printf "${GRY}%${W}s${R}\n" '' | tr ' ' '─'; }
title() { printf "\n${B}${CYN}%s${R}\n" "$1"; rule; }
kv()   { printf "  ${GRY}%-18s${R} %s\n" "$1" "$2"; }
ok()   { printf "  ${GRN}✓${R} %s\n" "$*"; }
bad()  { printf "  ${RED}✗${R} %s\n" "$*"; }
warn() { printf "  ${YEL}!${R} %s\n" "$*"; }
note() { printf "  ${GRY}%s${R}\n" "$*"; }
pause(){ printf "\n  ${GRY}Press Enter to continue…${R}"; read -r _ || { printf "\n"; exit 0; }; }

# item <key> <label> [detail]
item() { printf "  ${GRN}%2s${R})  ${B}%-22s${R} ${GRY}%s${R}\n" "$1" "$2" "${3:-}"; }

need_root() { [ "$(id -u)" -eq 0 ] || { bad "Run as root."; exit 1; }; }

# badge <state> — coloured status word of a fixed width
badge() {
    case "$1" in
        active)   printf "${GRN}● running${R}" ;;
        inactive) printf "${GRY}○ stopped${R}" ;;
        failed)   printf "${RED}● failed${R}"  ;;
        *)        printf "${YEL}● %s${R}" "$1" ;;
    esac
}

banner() {
    clear
    printf "${CYN}${B}"
    cat <<'ART'
   ┌─┐┌┬┐   ┌─┐┌┬┐┌─┐┬─┐┌─┐┌─┐┌┐┌┌─┐┬ ┬  ┌┬┐┬ ┬┌┐┌┌┐┌┌─┐┬
   ├┤  │    ├┤ │││├┤ ├┬┘│ ┬├┤ ││││  └┬┘   │ │ │││││││├┤ │
   └─┘ ┴    └─┘┴ ┴└─┘┴└─└─┘└─┘┘└┘└─┘ ┴    ┴ └─┘┘└┘┘└┘└─┘┴─┘
ART
    printf "${R}"
    local cv; cv="$(core_version)"
    printf "  ${GRY}panel ${R}${B}v%s${R}${GRY}   core ${R}${B}v%s${R}${GRY}   %s${R}\n" \
        "$SCRIPT_VERSION" "$cv" "$(uname -m)"
    # A half-applied update — a new core binary next to the panel it shipped
    # with replaced, or the reverse — looks like "the update did nothing": the
    # menus are the old ones even though the core is current. Say so here rather
    # than letting it be discovered protocol by protocol.
    if [ "$cv" != "—" ] && [ "$cv" != "$SCRIPT_VERSION" ]; then
        printf "  ${YEL}! panel v%s and core v%s are from different releases${R}\n" \
            "$SCRIPT_VERSION" "$cv"
        printf "  ${GRY}  leave this console and run 'et' again; if it persists, re-run the installer${R}\n"
    fi
    rule
}

# ============================================================================
# 2. Validation helpers — every prompt re-asks instead of aborting
# ============================================================================
ask() {  # ask <prompt> [default]
    local p="$1" d="${2:-}" a
    if [ -n "$d" ]; then printf "  %s ${GRY}[${R}${CYN}%s${R}${GRY}]${R}: " "$p" "$d" >&2
    else printf "  %s: " "$p" >&2; fi
    # A failed read means stdin closed (piped input exhausted, or the terminal
    # went away). Returning the default here would spin the menu forever, so
    # treat EOF as "leave", the same as choosing Exit.
    #
    # Every caller invokes this as $(ask …), so `exit` would only end the
    # command-substitution subshell and the menu would keep redrawing against a
    # closed stdin — an endless loop at full CPU. Signal the real shell instead;
    # the TERM trap installed at the top of the script turns it into a clean exit.
    if ! read -r a; then printf "\n" >&2; kill -TERM "$$" 2>/dev/null; exit 0; fi
    printf '%s' "${a:-$d}"
}
ask_req() { local v; while :; do v="$(ask "$1" "${2:-}")"; [ -n "$v" ] && { printf '%s' "$v"; return; }; bad "A value is required." >&2; done; }
yesno() { local a; a="$(ask "$1 ${GRY}(y/n)${R}" "${2:-n}")"; case "$a" in [Yy]*) return 0;; *) return 1;; esac; }

ask_port() {
    local v
    while :; do
        v="$(ask "$1" "${2:-}")"
        if [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 1 ] && [ "$v" -le 65535 ]; then
            if port_in_use "$v"; then warn "Port $v is already in use on this server." >&2
                yesno "Use it anyway?" "n" && { printf '%s' "$v"; return; }
                continue
            fi
            printf '%s' "$v"; return
        fi
        bad "Enter a port between 1 and 65535." >&2
    done
}
ask_choice() { # ask_choice <prompt> <default> <opt1> <opt2> ...
    local p="$1" d="$2"; shift 2
    local v opts="$*"
    while :; do
        v="$(ask "$p ${GRY}(${opts// /, })${R}" "$d")"
        for o in $opts; do [ "$v" = "$o" ] && { printf '%s' "$v"; return; }; done
        bad "Choose one of: ${opts// /, }" >&2
    done
}
valid_ipv4() {
    local ip="$1" o
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1:4}"; do [ "$o" -le 255 ] || return 1; done
    return 0
}
ask_ip() {
    local v
    while :; do
        v="$(ask "$1" "${2:-}")"
        valid_ipv4 "$v" && { printf '%s' "$v"; return; }
        # Accept a hostname too — the core resolves it at dial time.
        [[ "$v" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] && { printf '%s' "$v"; return; }
        bad "Enter a valid IPv4 address or hostname." >&2
    done
}
valid_ipv6() { [[ "$1" == *:* ]] && [[ "$1" =~ ^[0-9A-Fa-f:]+$ ]] && [[ "$1" != *:::* ]]; }
ask_ip6() {
    local v
    while :; do
        v="$(ask "$1" "${2:-}")"
        valid_ipv6 "$v" && { printf '%s' "$v"; return; }
        [[ "$v" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] && { printf '%s' "$v"; return; }
        bad "Enter an IPv6 address (e.g. 2a01:4f8::1) or a hostname with an AAAA record." >&2
    done
}

# host_has_ipv6 — a routable (non-link-local) IPv6 address on some interface.
host_has_ipv6() {
    [ -r /proc/net/if_inet6 ] || return 1
    ip -6 addr show scope global 2>/dev/null | grep -q 'inet6'
}

ask_name() {
    local v
    while :; do
        v="$(ask "$1" "${2:-}")"
        if [[ ! "$v" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,30}$ ]]; then
            bad "Use letters, digits, dash or underscore (max 31)." >&2; continue
        fi
        [ -f "${CONF_DIR}/${v}.toml" ] && { bad "A tunnel named '$v' already exists." >&2; continue; }
        printf '%s' "$v"; return
    done
}
port_in_use() { ss -Hltun 2>/dev/null | awk '{print $5}' | grep -qE "[:.]$1\$"; }

# ============================================================================
# 3. System + network probes
# ============================================================================
core_version() { [ -x "$CORE" ] && "$CORE" version 2>/dev/null | awk -F': *' '/Core Version/{print $2}' | tr -d 'v ' || echo "—"; }
cpu_cores()    { nproc 2>/dev/null || echo 1; }
has_aesni()    { grep -qm1 -E '\b(aes|aes_ni)\b' /proc/cpuinfo 2>/dev/null; }

cpu_usage() {
    local a b idle1 idle2 tot1 tot2
    read -r _ a <<< "$(grep -m1 '^cpu ' /proc/stat)"; set -- $a
    idle1=$4; tot1=0; for v in "$@"; do tot1=$((tot1+v)); done
    sleep 0.25
    read -r _ b <<< "$(grep -m1 '^cpu ' /proc/stat)"; set -- $b
    idle2=$4; tot2=0; for v in "$@"; do tot2=$((tot2+v)); done
    local dt=$((tot2-tot1)) di=$((idle2-idle1))
    [ "$dt" -le 0 ] && { echo 0; return; }
    echo $(( (100*(dt-di))/dt ))
}
mem_usage() { awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{if(t)printf "%d %d %d", (t-a)/1024, t/1024, 100*(t-a)/t}' /proc/meminfo; }

# bar <percent> [width] — a compact meter
bar() {
    local pct="${1:-0}" width="${2:-24}" filled colour
    [ "$pct" -gt 100 ] && pct=100
    filled=$(( pct*width/100 ))
    if   [ "$pct" -ge 90 ]; then colour="$RED"
    elif [ "$pct" -ge 70 ]; then colour="$YEL"
    else colour="$GRN"; fi
    printf "${colour}"; printf "%${filled}s" '' | tr ' ' '█'
    printf "${GRY}"; printf "%$((width-filled))s" '' | tr ' ' '░'
    printf "${R} %3d%%" "$pct"
}

SERVER_IP=""; SERVER_LOC=""; SERVER_ASN=""
fetch_identity() {
    [ -n "$SERVER_IP" ] && return
    local j=""
    have curl && j="$(curl -fsS --max-time 4 'http://ip-api.com/json/?fields=query,country,city,as' 2>/dev/null)"
    if [ -n "$j" ]; then
        SERVER_IP="$(grep -o '"query":"[^"]*"'  <<<"$j" | cut -d'"' -f4)"
        local c ci; c="$(grep -o '"country":"[^"]*"' <<<"$j" | cut -d'"' -f4)"
        ci="$(grep -o '"city":"[^"]*"' <<<"$j" | cut -d'"' -f4)"
        SERVER_LOC="${ci:+$ci, }${c:-?}"
        SERVER_ASN="$(grep -o '"as":"[^"]*"' <<<"$j" | cut -d'"' -f4)"
    fi
    [ -z "$SERVER_IP" ] && SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    : "${SERVER_IP:=unknown}" "${SERVER_LOC:=offline}" "${SERVER_ASN:=—}"
}

# ============================================================================
# 4. Tunnel registry + conflict-free allocation
# ============================================================================
list_tunnels() { [ -d "$CONF_DIR" ] && find "$CONF_DIR" -maxdepth 1 -name '*.toml' -printf '%f\n' 2>/dev/null | sed 's/\.toml$//' | sort || true; }
tunnel_count() { list_tunnels | grep -c . ; }
svc_state()   { systemctl is-active "${SVC_PREFIX}$1" 2>/dev/null || echo unknown; }
cfg_get()     { grep -E "^[[:space:]]*$2[[:space:]]*=" "${CONF_DIR}/$1.toml" 2>/dev/null | head -1 | sed 's/^[^=]*=[[:space:]]*//; s/^"//; s/"$//'; }

# next_free_port <start> — first port not used by a config or a live socket
next_free_port() {
    local p="$1" used
    used="$(grep -hE '^[[:space:]]*(tunnel_port|health_port)' "$CONF_DIR"/*.toml 2>/dev/null | grep -oE '[0-9]+' | sort -u)"
    while grep -qx "$p" <<<"$used" || port_in_use "$p"; do p=$((p+1)); done
    printf '%s' "$p"
}

# next_free_subnet — 10.10.N.0/24 with N stepping by 10, skipping taken ones
next_free_subnet() {
    local n=10 taken
    taken="$(grep -hE '^[[:space:]]*tun_ip' "$CONF_DIR"/*.toml 2>/dev/null | grep -oE '10\.10\.[0-9]+\.' | cut -d. -f3 | sort -un)"
    while grep -qx "$n" <<<"$taken"; do n=$((n+10)); [ "$n" -gt 250 ] && n=$((RANDOM%250)); done
    printf '%s' "$n"
}

# next_free_iface <base> — et0, et1, …
next_free_iface() {
    local i=0
    while grep -qs "\"${1}${i}\"" "$CONF_DIR"/*.toml 2>/dev/null || ip link show "${1}${i}" >/dev/null 2>&1; do i=$((i+1)); done
    printf '%s%s' "$1" "$i"
}

enable_ip_forwarding() {
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    local f=/etc/sysctl.d/99-emergency-tunnel.conf
    grep -qs '^net.ipv4.ip_forward *= *1' "$f" || echo "net.ipv4.ip_forward=1" >> "$f"
}

# apply_host_tuning — the sysctls the core can only advise about. Written to a
# dedicated file so it is reversible and never fights the distro's own config.
apply_host_tuning() {
    local f=/etc/sysctl.d/99-emergency-tunnel.conf
    {
        echo "# Written by Emergency Tunnel — safe to delete to revert."
        echo "net.ipv4.ip_forward=1"
        echo "net.core.default_qdisc=fq"
        echo "net.ipv4.tcp_congestion_control=bbr"
        echo "net.ipv4.tcp_slow_start_after_idle=0"
        echo "net.ipv4.tcp_rmem=4096 131072 16777216"
        echo "net.ipv4.tcp_wmem=4096 65536 16777216"
        echo "net.core.rmem_max=16777216"
        echo "net.core.wmem_max=16777216"
        echo "net.core.somaxconn=8192"
        echo "net.ipv4.tcp_mtu_probing=1"
        echo "net.ipv4.tcp_fastopen=3"
    } > "$f"
    modprobe tcp_bbr >/dev/null 2>&1
    sysctl -p "$f" >/dev/null 2>&1
}

# ============================================================================
# 5. Config writer
# ============================================================================
# Values are collected in the CFG associative array and written in one pass, so
# adding a core option means adding one line here and nothing else.
declare -A CFG

cfg_reset() { CFG=(); }
cfg_set()   { CFG["$1"]="$2"; }

write_config() {
    local name="${CFG[name]}" f="${CONF_DIR}/${CFG[name]}.toml"
    install -d -m 0750 "$CONF_DIR"
    umask 077
    {
        echo "# Emergency Tunnel — generated by et v${SCRIPT_VERSION} on $(date -u +%FT%TZ)"
        echo "# Section: ${CFG[_section]:-custom}    Protocol: ${CFG[_proto]:-?}"
        echo
        local k
        for k in name role engine transport mode peer tunnel_port \
                 ws_path ws_host low_latency token fec_data fec_parity \
                 tls_cert tls_key tls_sni tls_verify \
                 tun_mode spf_profile encapsulation spoof_src_ip spoof_dst_ip \
                 tun_ip tun_ip6 peer_tun_ip tun_iface mtu tun_queues \
                 workers pool cipher profile health_port log_level \
                 heartbeat_interval heartbeat_timeout batch_size channel_size \
                 so_sndbuf so_rcvbuf exit_host proxy_protocol forwards; do
            [ -n "${CFG[$k]:-}" ] || continue
            case "$k" in
                # numeric / boolean / array — emitted bare
                tunnel_port|mtu|workers|pool|health_port|tun_queues|\
                heartbeat_interval|heartbeat_timeout|batch_size|channel_size|\
                so_sndbuf|so_rcvbuf|proxy_protocol|forwards|low_latency|\
                fec_data|fec_parity|tls_verify)
                    echo "$k = ${CFG[$k]}" ;;
                *)  echo "$k = \"${CFG[$k]}\"" ;;
            esac
        done
    } > "$f"
    chmod 0600 "$f"
    printf '%s' "$f"
}

csv_to_toml_array() {
    local out="" tok; IFS=',' read -r -a parts <<< "$1"
    for tok in "${parts[@]}"; do tok="${tok//[[:space:]]/}"; [ -z "$tok" ] && continue
        out="${out:+$out, }\"${tok}\""; done
    printf '[%s]' "$out"
}

# ============================================================================
# 6. Optimiser — one place that decides every performance parameter
# ============================================================================
# Everything here is derived from the machine and the protocol, so a fresh
# install is already tuned and nothing needs hand-editing afterwards. Values the
# core already picks well (heartbeats, send buffers, frame budget) are
# deliberately NOT written: pinning them freezes a config at today's defaults
# and stops future core improvements from reaching it.

best_cipher() { has_aesni && echo "aes-256-gcm" || echo "chacha20-poly1305"; }

# link_pool — parallel links/sessions. More than the core count only adds
# context switching; below 2 loses the ability to overlap a stalled link.
link_pool() { local c; c=$(cpu_cores); [ "$c" -gt 4 ] && c=4; [ "$c" -lt 2 ] && c=2; printf '%s' "$c"; }

# perf_profile — the core's GC/buffer profile, from available RAM.
perf_profile() {
    local mb; mb=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
    if   [ "$mb" -ge 3500 ]; then echo fast
    elif [ "$mb" -ge 1200 ]; then echo balance
    else echo resource; fi
}

# optimise <section> <protocol> — fills CFG with tuned values.
optimise() {
    local section="$1" proto="$2"
    cfg_set _section "$section"; cfg_set _proto "$proto"
    cfg_set cipher    "$(best_cipher)"
    cfg_set profile   "$(perf_profile)"
    cfg_set pool      "$(link_pool)"
    cfg_set workers   0            # 0 = auto, cgroup-aware
    cfg_set log_level "info"

    case "$section" in
      basic)
        # The caller picks mux or direct; on a stream carrier the MTU is
        # irrelevant and the core's adaptive frame budget handles sizing, but the
        # reliable-UDP carrier needs one because it segments the stream itself.
        [ "$proto" = "udp" ] && cfg_set mtu 1400
        ;;
      tun)
        cfg_set engine tun
        cfg_set tun_queues "${CFG[pool]}"     # queues must equal links, both ends
        case "$proto" in
          tcp)  cfg_set mtu 1400 ;;           # stream carrier re-segments
          *)    cfg_set mtu 1320 ;;           # datagram carrier: leave header room
        esac
        ;;
      gaming)
        # Latency over bulk throughput: a datagram carrier (no head-of-line
        # blocking from carrier retransmits) and shallow queues, so a delayed
        # packet is dropped rather than delivered late — which is what a game
        # or voice codec wants.
        cfg_set engine tun
        cfg_set tun_mode udp
        cfg_set mtu 1320
        cfg_set pool 2                        # fewer queues = less reordering
        cfg_set tun_queues 2
        cfg_set channel_size 64               # ~25 ms of buffer at 20 Mbit
        cfg_set batch_size 8                  # small frames: less serialisation delay
        cfg_set heartbeat_interval 2          # notice a dead path in ~8 s
        cfg_set heartbeat_timeout 8
        # Tells the core (and the reliable-UDP ARQ, if this ever runs over it)
        # to favour latency: shorter timers, shallower windows, gentler backoff.
        cfg_set low_latency true
        cfg_set profile balance
        ;;
      spf)
        cfg_set engine spf
        cfg_set encapsulation ipx
        cfg_set mtu 1320
        cfg_set tun_queues "${CFG[pool]}"
        ;;
    esac
}

show_tuning() {
    title "Tuning chosen for this server"
    kv "CPU cores"      "$(cpu_cores)"
    kv "AES-NI"         "$(has_aesni && echo "yes → aes-256-gcm" || echo "no → chacha20-poly1305")"
    kv "Memory profile" "${CFG[profile]}"
    kv "Parallel links" "${CFG[pool]}"
    [ -n "${CFG[mtu]:-}" ]          && kv "MTU"          "${CFG[mtu]}"
    [ -n "${CFG[channel_size]:-}" ] && kv "Queue depth"  "${CFG[channel_size]} packets (latency-first)"
    note "Heartbeats, socket buffers and frame sizing are left to the core so"
    note "future tuning improvements reach this tunnel without an edit."
}

# ============================================================================
# 7. Sections
# ============================================================================
# role_prompt is captured with $(...), so every byte it prints on stdout becomes
# part of the answer — the menu itself must go to stderr.
role_prompt() {
    {
        echo
        note "Which end is this server?"
        item 1 "Iran (entry)"   "users connect here; listens for the tunnel"
        item 2 "Foreign (exit)" "runs the real service; dials the Iran server"
    } >&2
    local c; c="$(ask_choice "Role" "1" 1 2)"
    [ "$c" = "1" ] && printf iran || printf kharej
}

# common_endpoint — role, peer, tunnel port, health port
common_endpoint() {
    local role; role="$(role_prompt)"
    cfg_set role "$role"; cfg_set mode reverse
    local tp; tp="$(ask_port "Tunnel port ${GRY}(same on BOTH servers)${R}" "$(next_free_port 1234)")"
    cfg_set tunnel_port "$tp"
    if [ "$role" = "kharej" ]; then
        # bip dials over ICMPv6, so it needs the peer's IPv6 address. Asking for
        # an IPv4 one here produces a config that never connects — every queue
        # retrying "no suitable address found" forever.
        if [ "${CFG[tun_mode]:-}" = "bip" ]; then
            cfg_set peer "$(ask_ip6 "Iran server public IPv6 address")"
        else
            cfg_set peer "$(ask_ip "Iran server public IP")"
        fi
    fi
    cfg_set health_port "$(next_free_port 9090)"
}

section_basic() {
    banner
    title "Basic — reverse tunnel to a service port"
    note "Users connect to a port on the Iran server; traffic comes out on the"
    note "Foreign server. Choose the carrier that survives your path."
    echo
    item 1 "TCPMUX" "TCP, multiplexed — fastest; one frame per new connection"
    item 2 "TCP"    "TCP, one connection per user — plainest traffic shape"
    item 3 "WSMUX"  "WebSocket, multiplexed — passes CDNs and reverse proxies"
    item 4 "WS"     "WebSocket, one connection per user"
    item 5 "UDP"    "reliable UDP (ARQ) — for paths that throttle or block TCP"
    echo
    note "Multiplexed carriers reuse one authenticated connection for everything,"
    note "which removes a handshake per user connection — measurably faster on a"
    note "long path. The unmultiplexed variants trade that for a more ordinary"
    note "per-connection traffic shape."
    local c; c="$(ask_choice "Protocol" "1" 1 2 3 4 5)"
    cfg_reset
    case "$c" in
        1) optimise basic tcpmux; cfg_set engine mux;    cfg_set transport tcp ;;
        2) optimise basic tcp;    cfg_set engine direct; cfg_set transport tcp ;;
        3) optimise basic wsmux;  cfg_set engine mux;    cfg_set transport ws ;;
        4) optimise basic ws;     cfg_set engine direct; cfg_set transport ws ;;
        5) optimise basic udp;    cfg_set engine mux;    cfg_set transport udp ;;
    esac
    cfg_set name "$(ask_name "Tunnel name" "basic$(tunnel_count)")"
    common_endpoint
    if [ "${CFG[transport]}" = "ws" ]; then
        cfg_set ws_path "$(ask "WebSocket path ${GRY}(must match on both ends)${R}" "/live/stream")"
        [ "${CFG[role]}" = "kharej" ] && cfg_set ws_host "$(ask "Host header ${GRY}(CDN hostname, or blank)${R}" "")"
    fi
    forwards_prompt
    finish_tunnel
}

section_tun() {
    banner
    title "TUN — private network between the two servers"
    note "Creates a virtual interface on each side so the servers can reach each"
    note "other on private IPs with any IP protocol (TCP, UDP, ICMP)."
    echo
    item 1 "TCP"  "reliable carrier — most compatible, best throughput"
    item 2 "UDP"  "datagram carrier — lower overhead, no carrier retransmits"
    item 3 "ICMP" "inside ping packets — beta, needs CAP_NET_RAW"
    item 4 "BIP"  "inside ICMPv6 — beta, needs CAP_NET_RAW and IPv6 on BOTH servers"
    if ! host_has_ipv6; then
        echo; warn "This server has no global IPv6 address, so BIP cannot connect."
        note "BIP carries the link inside ICMPv6. Use ICMP for the same idea over IPv4."
    fi
    local c m
    while :; do
        c="$(ask_choice "Method" "1" 1 2 3 4)"
        case "$c" in 1) m=tcp;; 2) m=udp;; 3) m=icmp;; 4) m=bip;; esac
        [ "$m" = "bip" ] && ! host_has_ipv6 && {
            bad "No global IPv6 on this server — BIP would retry forever."
            yesno "Choose a different method?" "y" && continue
        }
        break
    done
    cfg_reset
    optimise tun "$m"; cfg_set tun_mode "$m"
    cfg_set name "$(ask_name "Tunnel name" "tun$(tunnel_count)")"
    common_endpoint
    tun_addressing
    forwards_prompt
    finish_tunnel
}

# ---- Backpack ----------------------------------------------------------------
# Carriers aimed at a path that is being filtered rather than merely slow. The
# menu lists only what the core actually implements: a protocol here means a
# working data plane, not a name.
gen_token() {
    if have openssl; then openssl rand -hex 24
    else head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}

section_backpack() {
    banner
    title "Backpack — for a path that is being filtered"
    note "Where the connection itself is blocked or throttled by how it looks,"
    note "a faster carrier does not help. These change what it looks like."
    echo
    item 1 "Stealth"   "TCP with no fingerprint — a wrong token gets no reply"
    item 2 "WSS"       "HTTPS with a Chrome fingerprint — serves a decoy website"
    item 3 "UDP + FEC" "reliable UDP with error correction — for lossy paths"
    echo
    note "Stealth looks like nothing at all; WSS looks like an ordinary website."
    note "Where the traffic pattern is being matched, either works — WSS is the"
    note "one that also passes a CDN, Stealth the one with nothing to match."
    local c; c="$(ask_choice "Method" "1" 1 2 3)"
    cfg_reset
    case "$c" in
        1) backpack_stealth ;;
        2) backpack_wss ;;
        3) backpack_fec ;;
    esac
}

backpack_wss() {
    optimise basic wsmux
    cfg_set engine "mux"
    cfg_set transport "wss"
    cfg_set name "$(ask_name "Tunnel name" "bp$(tunnel_count)")"
    echo
    note "Anything that is not a tunnel connection — a browser, a scanner, a"
    note "probe — is served an ordinary nginx welcome page over TLS."
    local h; h="$(ask "Hostname to present (a domain you own, or blank)" "")"
    [ -n "$h" ] && { cfg_set tls_sni "$h"; cfg_set ws_host "$h"; }
    cfg_set ws_path "/$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    note "Tunnel path: ${CFG[ws_path]}  (must match on BOTH servers)"
    if [ -n "$h" ] && yesno "Do you have a certificate for ${h}?" "n"; then
        cfg_set tls_cert "$(ask_req "Path to fullchain.pem")"
        cfg_set tls_key  "$(ask_req "Path to privkey.pem")"
        cfg_set tls_verify true
    else
        note "Using a generated self-signed certificate. The tunnel is unaffected —"
        note "its own handshake is what secures it — but a probe that checks the"
        note "chain will see it is not signed. A real certificate is better."
    fi
    common_endpoint
    forwards_prompt
    finish_tunnel
}

backpack_stealth() {
    optimise basic tcpmux
    cfg_set engine "mux"
    cfg_set transport "stealth"
    cfg_set name "$(ask_name "Tunnel name" "bp$(tunnel_count)")"
    local tok; tok="$(gen_token)"
    echo
    note "Token for this tunnel (copy it to the OTHER server verbatim):"
    printf "    ${B}${CYN}%s${R}\n\n" "$tok"
    if yesno "Is this the first server of the pair?" "y"; then
        cfg_set token "$tok"
    else
        cfg_set token "$(ask_req "Paste the token from the first server")"
    fi
    common_endpoint
    forwards_prompt
    finish_tunnel
}

backpack_fec() {
    optimise basic udp
    cfg_set engine "mux"
    cfg_set transport "udp"
    cfg_set name "$(ask_name "Tunnel name" "bp$(tunnel_count)")"
    echo
    note "Error correction sends parity packets alongside the data, so an"
    note "isolated loss is repaired without waiting a round trip for a resend."
    warn "Measured on this build it has not yet paid for itself — parity is added"
    warn "below congestion control, so it competes with the data it protects."
    note "Offered because a real lossy path may differ from the test path; compare"
    note "against a plain UDP tunnel before keeping it. Same values on BOTH servers."
    if yesno "Enable error correction?" "n"; then
        local d p
        d="$(ask "Data packets per group" "10")"
        p="$(ask "Parity packets per group" "3")"
        cfg_set fec_data "$d"; cfg_set fec_parity "$p"
        note "Bandwidth premium: about $(( 100 * p / (d>0?d:1) ))%."
    fi
    common_endpoint
    forwards_prompt
    finish_tunnel
}

section_gaming() {
    banner
    title "Gaming — latency-first tunnel"
    echo
    item 1 "UDP tunnel"  "encrypted TUN over UDP, tuned for latency over bulk"
    item 2 "WireGuard"   "kernel WireGuard — lowest overhead available"
    echo
    note "Both prioritise responsiveness over throughput. The UDP tunnel is part"
    note "of this platform and shows up in the dashboard; WireGuard runs in the"
    note "kernel, which costs less CPU per packet than anything in userspace can."
    local c; c="$(ask_choice "Method" "1" 1 2)"
    case "$c" in
        1) gaming_udp ;;
        2) gaming_wireguard ;;
    esac
}

gaming_udp() {
    cfg_reset
    optimise gaming udp
    cfg_set name "$(ask_name "Tunnel name" "game$(tunnel_count)")"
    common_endpoint
    tun_addressing
    forwards_prompt
    finish_tunnel
}

# ---- WireGuard ---------------------------------------------------------------
# WireGuard is not reimplemented here: the kernel module is faster than any
# userspace tunnel and is already present on every modern distribution. The
# panel does what a management system should — generate keys, allocate a
# conflict-free subnet and port, write the interface config, and hand over the
# exact peer block for the other server.
WG_DIR="/etc/wireguard"

wg_available() {
    have wg || { pkg_install_wg; }
    have wg
}
pkg_install_wg() {
    note "Installing wireguard-tools…"
    if   have apt-get; then DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools >/dev/null 2>&1
    elif have dnf;     then dnf install -y -q wireguard-tools >/dev/null 2>&1
    elif have yum;     then yum install -y -q wireguard-tools >/dev/null 2>&1
    elif have pacman;  then pacman -Sy --noconfirm --needed wireguard-tools >/dev/null 2>&1
    elif have apk;     then apk add --no-cache wireguard-tools >/dev/null 2>&1
    fi
    modprobe wireguard >/dev/null 2>&1
}

next_free_wg_subnet() {
    local n=100 taken
    taken="$(grep -hoE '10\.10\.[0-9]+\.' "$WG_DIR"/*.conf 2>/dev/null | cut -d. -f3 | sort -un)"
    while grep -qx "$n" <<<"$taken"; do n=$((n+10)); [ "$n" -gt 250 ] && n=$((RANDOM%250)); done
    printf '%s' "$n"
}
next_free_wg_iface() {
    local i=0
    while [ -f "${WG_DIR}/wg${i}.conf" ] || ip link show "wg${i}" >/dev/null 2>&1; do i=$((i+1)); done
    printf 'wg%s' "$i"
}

gaming_wireguard() {
    banner; title "Gaming — WireGuard"
    if ! wg_available; then
        bad "wireguard-tools could not be installed on this system."
        note "Install it manually, then re-run: apt install wireguard-tools"
        pause; return
    fi
    if ! modprobe wireguard >/dev/null 2>&1 && [ ! -d /sys/module/wireguard ]; then
        warn "The kernel WireGuard module is not loaded."
        note "On most VPS kernels it is built in; on a container it may be unavailable."
    fi
    install -d -m 0700 "$WG_DIR"

    local role iface port subnet myip peerip priv pub
    role="$(role_prompt)"
    iface="$(next_free_wg_iface)"
    port="$(ask_port "WireGuard UDP port ${GRY}(same on both servers)${R}" "$(next_free_port 51820)")"
    subnet="$(next_free_wg_subnet)"
    if [ "$role" = "iran" ]; then myip="10.10.${subnet}.1"; peerip="10.10.${subnet}.2"
    else                          myip="10.10.${subnet}.2"; peerip="10.10.${subnet}.1"; fi
    myip="$(ask "This server's tunnel IP" "${myip}")"
    peerip="$(ask "Peer's tunnel IP" "${peerip}")"

    priv="$(wg genkey)"; pub="$(printf '%s' "$priv" | wg pubkey)"
    local peerpub peerep=""
    echo
    note "Run this same option on the OTHER server first if you have not yet —"
    note "you need its public key to finish here."
    peerpub="$(ask "Peer's public key ${GRY}(leave blank to fill in later)${R}" "")"
    [ "$role" = "kharej" ] && peerep="$(ask_ip "Iran server public IP")"

    # MTU: 1420 is the standard WireGuard value on a 1500-byte path (20 IPv4 +
    # 8 UDP + 32 WireGuard + 8 = 1432 of headroom); lower it only if the path
    # fragments.
    local mtu; mtu="$(ask "MTU" "1420")"

    umask 077
    {
        echo "# Emergency Tunnel — WireGuard, generated by et v${SCRIPT_VERSION}"
        echo "[Interface]"
        echo "PrivateKey = ${priv}"
        echo "Address    = ${myip}/24"
        echo "ListenPort = ${port}"
        echo "MTU        = ${mtu}"
        echo
        echo "[Peer]"
        [ -n "$peerpub" ] && echo "PublicKey  = ${peerpub}" || echo "# PublicKey = <paste the peer's public key, then: systemctl restart wg-quick@${iface}>"
        echo "AllowedIPs = ${peerip}/32"
        [ -n "$peerep" ] && echo "Endpoint   = ${peerep}:${port}"
        # A keepalive is what holds a NAT mapping open; without it the first
        # packet after an idle period is lost and the game stutters on return.
        echo "PersistentKeepalive = 25"
    } > "${WG_DIR}/${iface}.conf"
    chmod 0600 "${WG_DIR}/${iface}.conf"

    echo; title "Created ${iface}"
    kv "Config"      "${WG_DIR}/${iface}.conf"
    kv "This server" "${myip}/24  (port ${port})"
    kv "Peer"        "${peerip}"
    kv "Public key"  "${pub}"
    echo
    note "Give the PUBLIC KEY above to the other server when it asks for one."

    if [ -n "$peerpub" ]; then
        systemctl enable --now "wg-quick@${iface}" >/dev/null 2>&1
        sleep 1
        if systemctl is-active --quiet "wg-quick@${iface}"; then
            ok "${iface} is up"
            wg show "${iface}" 2>/dev/null | sed 's/^/    /'
        else
            bad "wg-quick@${iface} did not start"
            systemctl --no-pager status "wg-quick@${iface}" 2>/dev/null | sed -n '1,8p' | sed 's/^/    /'
        fi
    else
        warn "Not started: the peer's public key is still missing."
        note "Add it to ${WG_DIR}/${iface}.conf, then: systemctl enable --now wg-quick@${iface}"
    fi
    pause
}

section_spf() {
    banner
    title "SPF — spoofed-source carrier (beta)"
    note "Wraps the encrypted link in ICMP or bare TCP with a rewritten source IP."
    note "Point-to-point only: inbound packets are accepted solely from the peer's"
    note "spoofed source. Requires Linux with CAP_NET_RAW on both servers."
    echo
    item 1 "ICMP" "echo-shaped, links demultiplexed by echo id"
    item 2 "TCP"  "bare TCP segments, links demultiplexed by source port"
    local c; c="$(ask_choice "Method" "1" 1 2)"
    cfg_reset
    local p; [ "$c" = "1" ] && p=icmp || p=tcp
    optimise spf "$p"; cfg_set spf_profile "$p"
    cfg_set name "$(ask_name "Tunnel name" "spf$(tunnel_count)")"
    common_endpoint
    echo
    note "Spoofing is mirrored: this server's src is the peer's dst and vice versa."
    cfg_set spoof_src_ip "$(ask_ip "This server's spoofed source IP")"
    cfg_set spoof_dst_ip "$(ask_ip "Peer's spoofed source IP")"
    tun_addressing
    forwards_prompt
    if [ "$p" = "tcp" ]; then
        echo; warn "For the TCP profile, drop the kernel's RSTs on BOTH servers:"
        note "iptables -A OUTPUT -p tcp --sport ${CFG[tunnel_port]} --tcp-flags RST RST -j DROP"
    fi
    finish_tunnel
}

# tun_addressing — private subnet, chosen so multiple tunnels never collide
tun_addressing() {
    local n ip peer
    n="$(next_free_subnet)"
    echo
    note "Private subnet for this tunnel (10.10.${n}.0/24 is free on this server)."
    if [ "${CFG[role]}" = "iran" ]; then ip="10.10.${n}.1"; peer="10.10.${n}.2"
    else                                 ip="10.10.${n}.2"; peer="10.10.${n}.1"; fi
    local a; a="$(ask "This server's tunnel IP" "${ip}/24")"
    cfg_set tun_ip "$a"
    cfg_set peer_tun_ip "$(ask "Peer's tunnel IP" "${peer}")"
    cfg_set tun_iface "$(next_free_iface et)"
    note "Interface: ${CFG[tun_iface]}   (peer must use the SAME subnet)"
}

forwards_prompt() {
    if [ "${CFG[role]}" != "iran" ]; then
        [ "${CFG[engine]}" = "mux" ] && cfg_set exit_host "$(ask "Service host on this server" "127.0.0.1")"
        return
    fi
    echo
    note "Port(s) your users connect to on this server."
    note "Formats: 443 · 443,8443 · 200-300 · 8000=9000   suffix @pp=PROXY protocol, @ll=low-latency"
    local l a
    while :; do
        l="$(ask_req "VPN/service port(s)" "443")"
        a="$(csv_to_toml_array "$l")"
        [ "$a" != "[]" ] && break
        bad "At least one port is required."
    done
    # Gaming forwards default to the low-latency class unless already tagged.
    if [ "${CFG[_section]}" = "gaming" ] && [[ "$a" != *"@ll"* ]]; then
        a="$(sed 's/"\([^"]*\)"/"\1@ll"/g' <<<"$a")"
        note "Tagged @ll (low-latency scheduling class)."
    fi
    cfg_set forwards "$a"
    [ "${CFG[engine]}" = "mux" ] && { yesno "Enable PROXY protocol v2?" "n" && cfg_set proxy_protocol true || cfg_set proxy_protocol false; }
}

# finish_tunnel — write, validate, check conflicts, start
finish_tunnel() {
    echo; show_tuning
    local f; f="$(write_config)"
    title "Validating"
    if ! "$CORE" validate --config "$f"; then
        bad "Configuration rejected — saved at $f but not started."; pause; return
    fi
    ok "configuration valid"
    local out
    if ! out="$("$CORE" check-conflicts --config "$f" --dir "$CONF_DIR" 2>&1 >/dev/null)"; then
        bad "Conflicts with an existing tunnel:"; sed 's/^/    /' <<<"$out"
        warn "Saved but not started. Edit it, or delete and recreate."; pause; return
    fi
    ok "no conflicts with the $(tunnel_count) existing tunnel(s)"

    [ -n "${CFG[forwards]:-}" ] && [ "${CFG[engine]}" != "mux" ] && enable_ip_forwarding
    apply_host_tuning
    ok "host network tuning applied (BBR, fq, buffers)"

    systemctl enable --now "${SVC_PREFIX}${CFG[name]}" >/dev/null 2>&1
    sleep 1.5
    if [ "$(svc_state "${CFG[name]}")" = "active" ]; then
        ok "tunnel '${CFG[name]}' is $(badge active)"
        echo; note "Now create the matching tunnel on the OTHER server with:"
        note "  • the same tunnel port (${CFG[tunnel_port]})"
        [ -n "${CFG[tun_ip]:-}" ] && note "  • the same subnet (${CFG[tun_ip]%/*} ↔ ${CFG[peer_tun_ip]})"
        [ -n "${CFG[ws_path]:-}" ] && note "  • the same WebSocket path (${CFG[ws_path]})"
        note "  • the same pool/queue count (${CFG[pool]})"
    else
        bad "tunnel failed to start"
        systemctl --no-pager status "${SVC_PREFIX}${CFG[name]}" 2>/dev/null | sed -n '1,8p' | sed 's/^/    /'
    fi
    pause
}

new_tunnel_menu() {
    while :; do
        banner
        title "Create a tunnel"
        item 1 "Basic"  "service-port tunnel — TCP, TCPMUX, WS, WSMUX, UDP"
        item 2 "TUN"    "private subnet between servers — TCP, UDP, ICMP, BIP"
        item 3 "Gaming" "latency-first — UDP tunnel or kernel WireGuard"
        item 4 "SPF"    "spoofed-source carrier — ICMP, TCP (beta)"
        item 5 "Backpack" "filtering-resistant — Stealth, and the coded carriers"
        item 0 "Back"   ""
        echo
        case "$(ask "Section" "1")" in
            1) section_basic ;; 2) section_tun ;;
            3) section_gaming ;; 4) section_spf ;;
            5) section_backpack ;;
            0|q) return ;;
            *) bad "Unknown choice."; sleep 1 ;;
        esac
    done
}

# ============================================================================
# 8. Tunnel management
# ============================================================================
pick_tunnel() {
    local ts=(); mapfile -t ts < <(list_tunnels)
    [ "${#ts[@]}" -eq 0 ] && { warn "No tunnels configured yet." >&2; return 1; }
    echo >&2
    local i
    for i in "${!ts[@]}"; do
        printf "  ${GRN}%2d${R})  ${B}%-18s${R} %b  ${GRY}%s/%s${R}\n" \
            "$((i+1))" "${ts[$i]}" "$(badge "$(svc_state "${ts[$i]}")")" \
            "$(cfg_get "${ts[$i]}" engine)" "$(cfg_get "${ts[$i]}" transport)$(cfg_get "${ts[$i]}" tun_mode)" >&2
    done
    local c; c="$(ask "Select" "1")"
    local idx=$((c-1))
    [ "$idx" -ge 0 ] 2>/dev/null && [ -n "${ts[$idx]:-}" ] || { bad "Invalid selection." >&2; return 1; }
    printf '%s' "${ts[$idx]}"
}

manage_menu() {
    local n; n="$(pick_tunnel)" || { pause; return; }
    while :; do
        banner
        title "Tunnel: ${n}"
        kv "State"    "$(badge "$(svc_state "$n")")"
        kv "Engine"   "$(cfg_get "$n" engine) / $(cfg_get "$n" transport)$(cfg_get "$n" tun_mode)$(cfg_get "$n" spf_profile)"
        kv "Role"     "$(cfg_get "$n" role)"
        kv "Port"     "$(cfg_get "$n" tunnel_port)"
        [ -n "$(cfg_get "$n" tun_ip)" ] && kv "Subnet" "$(cfg_get "$n" tun_ip) ↔ $(cfg_get "$n" peer_tun_ip)"
        echo
        item 1 "Start";    item 2 "Stop";  item 3 "Restart"
        item 4 "Live logs"; item 5 "Statistics"; item 6 "Health check"
        item 7 "Edit config"; item 8 "Show config"; item 9 "Delete"
        item 0 "Back"
        echo
        case "$(ask "Action" "5")" in
            1) systemctl start "${SVC_PREFIX}$n"   && ok started   || bad failed; sleep 1 ;;
            2) systemctl stop "${SVC_PREFIX}$n"    && ok stopped   || bad failed; sleep 1 ;;
            3) systemctl restart "${SVC_PREFIX}$n" && ok restarted || bad failed; sleep 1 ;;
            4) show_logs "$n" ;;
            5) show_stats "$n"; pause ;;
            6) health_check "$n"; pause ;;
            7) edit_config "$n" ;;
            8) banner; title "${CONF_DIR}/${n}.toml"; sed 's/^/  /' "${CONF_DIR}/${n}.toml"; pause ;;
            9) delete_tunnel "$n" && return ;;
            0|q) return ;;
        esac
    done
}

show_logs() {
    banner; title "Live logs — $1  ${GRY}(Ctrl-C to return)${R}"
    ( trap 'exit 0' INT
      journalctl -u "${SVC_PREFIX}$1" -n 80 -f --no-pager 2>/dev/null \
        || tail -n 80 -f "${LOG_DIR}/$1.log" )
    pause
}

# stats_json <tunnel> — the core's /stats, or empty
stats_json() {
    local hp; hp="$(cfg_get "$1" health_port)"
    [ -n "$hp" ] && have curl || return 1
    curl -fsS --max-time 2 --noproxy '*' "http://127.0.0.1:${hp}/stats" 2>/dev/null
}
jget() { grep -o "\"$2\":[^,}]*" <<<"$1" | head -1 | cut -d: -f2- | tr -d '" '; }

show_stats() {
    local n="$1" j; j="$(stats_json "$n")" || { warn "Tunnel is not running or has no health port."; return; }
    [ -z "$j" ] && { warn "No statistics available (is it running?)"; return; }
    title "Statistics — $n"
    local links rtt tx rx drop
    links="$(jget "$j" live_links)"; [ -z "$links" ] && links="$(jget "$j" sessions)"
    rtt="$(jget "$j" rtt_ms)"; tx="$(jget "$j" tx_bytes)"; rx="$(jget "$j" rx_bytes)"
    drop="$(jget "$j" tx_dropped)"
    kv "Live links"   "${links:-0}"
    kv "Link RTT"     "${rtt:-?} ms   ${GRY}(the tunnel's own round trip)${R}"
    kv "Sent"         "$(human "${tx:-0}")"
    kv "Received"     "$(human "${rx:-0}")"
    [ -n "$drop" ] && kv "AQM drops" "${drop}  ${GRY}(steady under load is healthy)${R}"
    local ex bu; ex="$(jget "$j" express_packets)"; bu="$(jget "$j" bulk_packets)"
    [ -n "$ex" ] && kv "Express/bulk" "${ex} / ${bu}  ${GRY}(latency-critical vs throughput)${R}"
    local q pq; q="$(jget "$j" queued_bytes)"; pq="$(jget "$j" peak_queued_bytes)"
    [ -n "$q" ] && kv "Egress queue" "$(human "$q") (peak $(human "${pq:-0}"))"
}

human() {
    local b="${1:-0}"
    awk -v b="$b" 'BEGIN{u="B";s=b;
      if(s>=1073741824){s/=1073741824;u="GiB"}else if(s>=1048576){s/=1048576;u="MiB"}
      else if(s>=1024){s/=1024;u="KiB"};printf "%.1f %s",s,u}'
}

health_check() {
    local n="$1"
    title "Health check — $n"
    [ "$(svc_state "$n")" = "active" ] && ok "service is running" || bad "service is not running"
    local hp; hp="$(cfg_get "$n" health_port)"
    if [ -n "$hp" ] && curl -fsS --max-time 2 --noproxy '*' "http://127.0.0.1:${hp}/health" >/dev/null 2>&1; then
        ok "core health endpoint responds"
    else bad "core health endpoint not responding"; fi
    local peer; peer="$(cfg_get "$n" peer_tun_ip)"
    if [ -n "$peer" ] && have ping; then
        printf "  ${GRY}pinging peer %s …${R}\n" "$peer"
        local out; out="$(ping -c 5 -i 0.3 -W 2 -q "$peer" 2>/dev/null)"
        if grep -q 'rtt\|round-trip' <<<"$out"; then
            ok "peer reachable — $(grep -oE '= [0-9./]+ ms' <<<"$out")"
            local loss; loss="$(grep -oE '[0-9]+% packet loss' <<<"$out")"
            [ "${loss%\%*}" = "0" ] && ok "no packet loss" || warn "packet loss: $loss"
        else bad "peer $peer did not answer — is the other side up?"; fi
    fi
    local tp; tp="$(cfg_get "$n" tunnel_port)"
    [ -n "$tp" ] && { port_in_use "$tp" && ok "tunnel port $tp is bound" || warn "tunnel port $tp is not bound"; }
}

edit_config() {
    local n="$1" f="${CONF_DIR}/$1.toml" bak
    bak="$(mktemp)"; cp "$f" "$bak"
    "${EDITOR:-nano}" "$f"
    if "$CORE" validate --config "$f"; then
        ok "valid — restarting"
        systemctl restart "${SVC_PREFIX}$n" >/dev/null 2>&1
    else
        bad "invalid — restoring the previous configuration"
        cp "$bak" "$f"
    fi
    rm -f "$bak"; pause
}

delete_tunnel() {
    local n="$1"
    echo; warn "This removes the tunnel '$n' and its configuration."
    yesno "Delete '$n'?" "n" || return 1
    systemctl disable --now "${SVC_PREFIX}$n" >/dev/null 2>&1
    "$CORE" firewall-down --config "${CONF_DIR}/${n}.toml" >/dev/null 2>&1
    rm -f "${CONF_DIR}/${n}.toml" "${LOG_DIR}/${n}.log"
    systemctl daemon-reload >/dev/null 2>&1
    ok "deleted '$n'"; pause; return 0
}

# ============================================================================
# 9. Dashboard
# ============================================================================
dashboard() {
    while :; do
        banner
        fetch_identity
        title "Server"
        kv "Public IP"  "$SERVER_IP"
        kv "Location"   "$SERVER_LOC"
        kv "Network"    "$SERVER_ASN"
        kv "Uptime"     "$(uptime -p 2>/dev/null | sed 's/^up //')"
        read -r used total pct <<< "$(mem_usage)"
        printf "  ${GRY}%-18s${R} %b\n" "CPU"    "$(bar "$(cpu_usage)")"
        printf "  ${GRY}%-18s${R} %b  ${GRY}%s/%s MiB${R}\n" "Memory" "$(bar "$pct")" "$used" "$total"

        title "Tunnels"
        local n any=0
        while IFS= read -r n; do
            [ -n "$n" ] || continue; any=1
            local j rtt links kind
            kind="$(cfg_get "$n" engine)/$(cfg_get "$n" transport)$(cfg_get "$n" tun_mode)$(cfg_get "$n" spf_profile)"
            j="$(stats_json "$n")" || j=""
            rtt="$(jget "$j" rtt_ms)"; links="$(jget "$j" live_links)"
            [ -z "$links" ] && links="$(jget "$j" sessions)"
            printf "  %b  ${B}%-14s${R} ${GRY}%-14s${R} links ${B}%-3s${R} rtt ${B}%-7s${R} ${GRY}%s${R}\n" \
                "$(badge "$(svc_state "$n")")" "$n" "$kind" "${links:-0}" \
                "${rtt:+${rtt}ms}" "$(cfg_get "$n" tun_ip)"
        done < <(list_tunnels)
        [ "$any" = "0" ] && note "No tunnels yet — create one from the main menu."

        echo; note "r = refresh · Enter = back"
        # bash returns >128 on a read timeout and 1 on EOF: refresh on the
        # former, leave on the latter (never spin).
        local k rc; read -r -t 5 k; rc=$?
        if   [ "$rc" -gt 128 ]; then continue
        elif [ "$rc" -ne 0 ];  then return
        fi
        [ "$k" = "r" ] || return
    done
}

# ============================================================================
# 10. Migration, updates, main menu
# ============================================================================
# migrate_configs brings pre-2.0 configs forward. It only ever REMOVES pinned
# values that now have better core defaults, and never rewrites a tunnel's
# identity, so an existing tunnel keeps working across the upgrade.
migrate_configs() {
    local changed=0 n f
    install -d -m 0755 "$STATE_DIR"
    while IFS= read -r n; do
        [ -n "$n" ] || continue
        f="${CONF_DIR}/${n}.toml"
        local before; before="$(md5sum "$f" | cut -d' ' -f1)"
        # 1.10 and earlier pinned the old slow heartbeats into every config,
        # which blocks the 3s/12s failover the core now defaults to.
        if grep -qE '^[[:space:]]*heartbeat_(interval|timeout)[[:space:]]*=[[:space:]]*(10|25)[[:space:]]*$' "$f"; then
            sed -i -E '/^[[:space:]]*heartbeat_(interval|timeout)[[:space:]]*=[[:space:]]*(10|25)[[:space:]]*$/d' "$f"
        fi
        # A pinned so_sndbuf defeats TCP_NOTSENT_LOWAT and reintroduces
        # multi-megabyte bufferbloat; the core autotunes better.
        sed -i -E '/^[[:space:]]*so_sndbuf[[:space:]]*=[[:space:]]*[0-9]+/d' "$f"
        # channel_size 1024 was the old bufferbloat default.
        sed -i -E 's/^[[:space:]]*channel_size[[:space:]]*=[[:space:]]*1024[[:space:]]*$//' "$f"
        [ "$(md5sum "$f" | cut -d' ' -f1)" != "$before" ] && { changed=$((changed+1)); cp "$f" "${STATE_DIR}/${n}.toml.pre2"; }
    done < <(list_tunnels)
    [ "$changed" -gt 0 ] && {
        ok "migrated $changed configuration(s) to v${SCRIPT_VERSION} defaults"
        note "originals saved in ${STATE_DIR}"
        systemctl daemon-reload >/dev/null 2>&1
    }
    return 0
}

update_core() {
    banner; title "Update"
    local url; url="$(cat "${LIB_DIR}/UPDATE_URL" 2>/dev/null || echo "")"
    [ -z "$url" ] && { bad "No update URL recorded — reinstall to set one."; pause; return; }
    kv "Installed" "v$(core_version)"
    kv "Source"    "$url"
    yesno "Download and install the latest version?" "y" || return
    if curl -fsSL "$url" | bash; then
        ok "update complete"; migrate_configs
        # The file on disk is new; this process is not. A shell runs the script
        # it was started with, so without re-execing, the console keeps showing
        # the old version and the old menus — a new section simply is not there —
        # while the core reports the new version, because that is read by running
        # et-core afresh each time. That reads exactly like a broken update.
        echo
        note "Restarting the console on the new version…"
        sleep 1
        exec "$PANEL" || exec et
    else bad "update failed — the existing install is untouched"; fi
    pause
}

speed_test() {
    banner; title "Throughput test"
    local n; n="$(pick_tunnel)" || { pause; return; }
    local peer; peer="$(cfg_get "$n" peer_tun_ip)"
    if [ -z "$peer" ]; then
        warn "Throughput testing needs a TUN/SPF tunnel with a peer address."
        note "For a Basic tunnel, measure through the forwarded port from a client."
        pause; return
    fi
    have iperf3 || { warn "iperf3 is not installed."; note "Install it on BOTH servers: apt install iperf3"; pause; return; }
    note "Run this on the PEER first:   iperf3 -s"
    yesno "Is iperf3 -s running on ${peer}?" "n" || { pause; return; }
    echo; iperf3 -c "$peer" -t 10 -P 4 2>&1 | sed 's/^/  /'
    pause
}

main_menu() {
    while :; do
        banner
        local total active=0 n
        total="$(tunnel_count)"
        while IFS= read -r n; do [ -n "$n" ] && [ "$(svc_state "$n")" = "active" ] && active=$((active+1)); done < <(list_tunnels)
        printf "  ${GRY}%s tunnel(s) configured · ${R}${GRN}%s running${R}\n\n" "$total" "$active"
        item 1 "Dashboard"      "live status, resources, per-tunnel health"
        item 2 "Create tunnel"  "Basic · TUN · Gaming · SPF · Backpack"
        item 3 "Manage tunnels" "start, stop, logs, stats, edit, delete"
        item 4 "Speed test"     "iperf3 across the tunnel"
        item 5 "Host tuning"    "apply BBR, fq and buffer sysctls"
        item 6 "Update"         "upgrade core and panel"
        item 0 "Exit"           ""
        echo
        case "$(ask "Choice" "1")" in
            1) dashboard ;;
            2) new_tunnel_menu ;;
            3) manage_menu ;;
            4) speed_test ;;
            5) banner; title "Host tuning"; apply_host_tuning; ok "applied and persisted to /etc/sysctl.d/99-emergency-tunnel.conf"
               sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc 2>/dev/null | sed 's/^/  /'; pause ;;
            6) update_core ;;
            0|q|quit|exit) clear; exit 0 ;;
            *) bad "Unknown choice."; sleep 1 ;;
        esac
    done
}

# ---- non-interactive entry points ------------------------------------------
case "${1:-}" in
    --version|-v) echo "et ${SCRIPT_VERSION} (core $(core_version))"; exit 0 ;;
    --list)       list_tunnels; exit 0 ;;
    --status)     for n in $(list_tunnels); do printf "%-20s %s\n" "$n" "$(svc_state "$n")"; done; exit 0 ;;
    --migrate)    need_root; migrate_configs; exit 0 ;;
    --tune)       need_root; apply_host_tuning; echo "host tuning applied"; exit 0 ;;
    --help|-h)    sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
esac

need_root
[ -x "$CORE" ] || { bad "et-core is not installed at ${CORE}"; exit 1; }
migrate_configs >/dev/null 2>&1
main_menu
