#!/usr/bin/env bash
#
# Emergency Tunnel — interactive management panel.
# Installed as: /usr/local/bin/et
#
set -uo pipefail

SCRIPT_VERSION="1.0.0"
CORE="/usr/local/bin/et-core"
CONF_DIR="/etc/emergency-tunnel"
LOG_DIR="/var/log/emergency-tunnel"
SVC_PREFIX="emergency-tunnel@"

C_RESET='\033[0m'; C_R='\033[0;31m'; C_G='\033[0;32m'; C_Y='\033[1;33m'
C_B='\033[0;34m'; C_C='\033[0;36m'; C_M='\033[0;35m'; C_BOLD='\033[1m'
LINE="═══════════════════════════════════════════════════"

need_root() { [ "$(id -u)" -eq 0 ] || { echo -e "${C_R}Run as root.${C_RESET}"; exit 1; }; }
pause() { echo; read -r -p "Press Enter to continue..." _; }
have()  { command -v "$1" >/dev/null 2>&1; }

core_version() { [ -x "$CORE" ] && "$CORE" version 2>/dev/null | awk -F': *' '{print $2}' || echo "not installed"; }
core_status()  { [ -x "$CORE" ] && echo -e "${C_G}installed${C_RESET}" || echo -e "${C_R}missing${C_RESET}"; }

list_tunnels() {
    [ -d "$CONF_DIR" ] || return 0
    find "$CONF_DIR" -maxdepth 1 -name '*.toml' -printf '%f\n' 2>/dev/null | sed 's/\.toml$//' | sort
}

count_active() {
    local n=0 t
    while IFS= read -r t; do
        [ -n "$t" ] || continue
        systemctl is-active --quiet "${SVC_PREFIX}${t}" && n=$((n+1))
    done < <(list_tunnels)
    echo "$n"
}

# --- Server identity (IP / geo / ASN), cached for the session ----------------
SERVER_IP=""; SERVER_LOC=""; SERVER_DC=""
fetch_identity() {
    [ -n "$SERVER_IP" ] && return
    SERVER_IP="fetching..."; SERVER_LOC="..."; SERVER_DC="..."
    local json=""
    if have curl; then
        json="$(curl -fsS --max-time 4 'http://ip-api.com/json/?fields=query,country,city,as,isp' 2>/dev/null)"
    fi
    if [ -n "$json" ] && have grep; then
        SERVER_IP="$(echo "$json"  | grep -o '"query":"[^"]*"'   | cut -d'"' -f4)"
        local country city as isp
        country="$(echo "$json" | grep -o '"country":"[^"]*"' | cut -d'"' -f4)"
        city="$(echo "$json"    | grep -o '"city":"[^"]*"'    | cut -d'"' -f4)"
        as="$(echo "$json"      | grep -o '"as":"[^"]*"'      | cut -d'"' -f4)"
        isp="$(echo "$json"     | grep -o '"isp":"[^"]*"'     | cut -d'"' -f4)"
        SERVER_LOC="${city:+$city, }${country:-unknown}"
        SERVER_DC="${as:-${isp:-unknown}}"
    fi
    [ -z "$SERVER_IP" ] && SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    [ -z "$SERVER_IP" ] && SERVER_IP="unknown"
    [ -z "$SERVER_LOC" ] && SERVER_LOC="unknown (offline)"
    [ -z "$SERVER_DC" ]  && SERVER_DC="unknown"
}

banner() {
    clear
    echo -e "${C_C}${C_BOLD}"
    cat <<'ART'
 ___                                             _____                       _
| __|_ __  ___ _ _ __ _ ___ _ _  __ _  _    _ _ |_   _|  _ _ _ _ _  ___ | |
| _|| '  \/ -_) '_/ _` / -_) ' \/ _| || |  | ' \  | || || | ' \ ' \/ -_)| |
|___|_|_|_\___|_| \__, \___|_||_\__|\_, |  |_||_| |_| \_,_|_||_|_||_\___||_|
                  |___/             |__/
ART
    echo -e "${C_RESET}"
    echo -e "                 ${C_BOLD}Emergency Tunnel${C_RESET}"
    echo -e "     Script Version: ${C_G}v${SCRIPT_VERSION}${C_RESET}    Core Version: ${C_G}v$(core_version)${C_RESET}"
    echo -e "${C_B}${LINE}${C_RESET}"
    fetch_identity
    printf "  ${C_BOLD}%-16s${C_RESET} %s\n" "IP Address:"    "${SERVER_IP}"
    printf "  ${C_BOLD}%-16s${C_RESET} %s\n" "Location:"      "${SERVER_LOC}"
    printf "  ${C_BOLD}%-16s${C_RESET} %s\n" "Datacenter:"    "${SERVER_DC}"
    printf "  ${C_BOLD}%-16s${C_RESET} %b\n" "Core Status:"   "$(core_status)"
    printf "  ${C_BOLD}%-16s${C_RESET} %s\n" "Active Tunnels:" "$(count_active) / $(list_tunnels | grep -c . || echo 0)"
    echo -e "${C_B}${LINE}${C_RESET}"
}

# --- Small input helpers -----------------------------------------------------
ask() { # ask "Prompt" "default" -> echoes value
    local prompt="$1" def="${2:-}" ans
    if [ -n "$def" ]; then read -r -p "$(echo -e "  ${prompt} [${C_C}${def}${C_RESET}]: ")" ans
    else read -r -p "$(echo -e "  ${prompt}: ")" ans; fi
    echo "${ans:-$def}"
}
yesno() { local p="$1" d="${2:-n}" a; a="$(ask "$p (y/n)" "$d")"; case "$a" in [Yy]*) return 0;; *) return 1;; esac; }

# --- Validating input helpers (re-prompt until valid; never abort) ----------
ask_req() { # prompt [default] — non-empty
    local v
    while true; do
        v="$(ask "$1" "${2:-}")"
        [ -n "$v" ] && { echo "$v"; return; }
        echo -e "  ${C_R}A value is required. Please try again.${C_RESET}" >&2
    done
}
ask_port() { # prompt [default] — 1..65535
    local v
    while true; do
        v="$(ask "$1" "${2:-}")"
        if [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 1 ] && [ "$v" -le 65535 ]; then echo "$v"; return; fi
        echo -e "  ${C_R}Invalid port. Enter a number between 1 and 65535.${C_RESET}" >&2
    done
}
valid_ipv4() { # ip -> returns 0 if a valid dotted-quad
    local ip="$1" o
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
        [ "$o" -le 255 ] || return 1
    done
    return 0
}
ask_ipcidr() { # prompt [default] — IPv4/prefix, e.g. 10.10.10.1/24
    local v ip prefix
    while true; do
        v="$(ask "$1" "${2:-}")"
        ip="${v%/*}"; prefix="${v#*/}"
        if [ "$v" != "$ip" ] && valid_ipv4 "$ip" && [[ "$prefix" =~ ^[0-9]+$ ]] && [ "$prefix" -ge 8 ] && [ "$prefix" -le 32 ]; then
            echo "$v"; return
        fi
        echo -e "  ${C_R}Invalid address. Use IP/prefix, e.g. 10.10.10.1/24.${C_RESET}" >&2
    done
}
ask_name() { # prompt [default] — alnum/_/- only, non-empty
    local raw v
    while true; do
        raw="$(ask "$1" "${2:-}")"
        v="$(printf '%s' "$raw" | tr -cd '[:alnum:]_-')"
        [ -n "$v" ] && { echo "$v"; return; }
        echo -e "  ${C_R}Invalid name — use letters, numbers, _ or -.${C_RESET}" >&2
    done
}
ask_choice() { # prompt default max — integer 1..max
    local v max="$3"
    while true; do
        v="$(ask "$1" "$2")"
        if [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 1 ] && [ "$v" -le "$max" ]; then echo "$v"; return; fi
        echo -e "  ${C_R}Please enter a number between 1 and ${max}.${C_RESET}" >&2
    done
}
ask_int() { # prompt default min max
    local v min="$3" max="$4"
    while true; do
        v="$(ask "$1" "$2")"
        if [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge "$min" ] && [ "$v" -le "$max" ]; then echo "$v"; return; fi
        echo -e "  ${C_R}Enter a number between ${min} and ${max}.${C_RESET}" >&2
    done
}
ask_oneof() { # prompt default "a b c"
    local v def="$2" opts="$3"
    while true; do
        v="$(ask "$1" "$def")"
        for o in $opts; do [ "$v" = "$o" ] && { echo "$v"; return; }; done
        echo -e "  ${C_R}Choose one of: ${opts}.${C_RESET}" >&2
    done
}

# --- Create tunnel wizard ----------------------------------------------------
create_tunnel() {
    banner
    echo -e "  ${C_BOLD}Create New Tunnel${C_RESET}\n"

    echo -e "  Which server is THIS host?"
    echo -e "    ${C_G}1)${C_RESET} Iran   — origin server, users connect here"
    echo -e "    ${C_G}2)${C_RESET} Kharej — foreign exit server (runs Xray/services)"
    local role; [ "$(ask_choice "Select" "1" 2)" = "2" ] && role="kharej" || role="iran"

    echo; echo -e "  Tunnel protocol:"
    echo -e "    ${C_G}1)${C_RESET} TCP Reverse Tunnel — multiplexed, lowest latency ${C_Y}[recommended, default]${C_RESET}"
    echo -e "    ${C_G}2)${C_RESET} TUN                — virtual network interface, routes all IP traffic"
    local engine transport="tcp"
    [ "$(ask_choice "Select" "1" 2)" = "2" ] && engine="tun" || engine="mux"

    # TUN carrier mode. Shown immediately after selecting TUN.
    local tun_mode="tcp"
    if [ "$engine" = "tun" ]; then
        echo; echo -e "  ${C_BOLD}TUN mode${C_RESET} (how the encrypted tunnel between the servers is carried):"
        echo -e "    ${C_G}1)${C_RESET} TCP  — TCP transport over the TUN network ${C_Y}[recommended]${C_RESET}"
        echo -e "         ${C_C}Uses TCP between the servers; tunnel traffic then flows through the"
        echo -e "         private tunnel IP addresses (10.10.10.x).${C_RESET}"
        echo -e "    ${C_G}2)${C_RESET} UDP  — UDP datagrams (lower overhead, good for gaming/VoIP)"
        echo -e "    ${C_G}3)${C_RESET} ICMP — carried inside ICMP echo (ping) ${C_Y}[beta, Linux, CAP_NET_RAW]${C_RESET}"
        echo -e "    ${C_G}4)${C_RESET} BIP  — ICMP over IPv6 ${C_Y}[beta, Linux, CAP_NET_RAW]${C_RESET}"
        case "$(ask_choice "Select" "1" 4)" in
            2) tun_mode="udp";; 3) tun_mode="icmp";; 4) tun_mode="bip";; *) tun_mode="tcp";;
        esac
    fi

    # Direction is fixed: reverse (Kharej dials Iran). Direct mode was removed.
    local mode="reverse"

    # Name: valid characters + unique. Re-prompts; never aborts.
    local defname="et$RANDOM"; defname="${defname:0:8}"
    local name
    while true; do
        name="$(ask_name "Tunnel name" "$defname")"
        [ -f "${CONF_DIR}/${name}.toml" ] || break
        echo -e "  ${C_R}A tunnel named '$name' already exists — choose another.${C_RESET}"
    done

    # Reverse mode: the Foreign (Kharej) server dials, so it needs the peer address.
    local peer=""
    [ "$role" = "kharej" ] && peer="$(ask_req "Iran server public IP or hostname")"

    local iface="emergency-tun" mtu profile workers pool cipher tunnel_port health
    local tun_ip="" peer_tun_ip="" forwards_toml="[]" proxy="false"

    tunnel_port="$(ask_port "Tunnel port (server <-> server link — SAME on both servers)" "1234")"
    mtu="$(ask_int "MTU" "1380" 576 9000)"
    profile="$(ask_oneof "Performance profile (fast=throughput | balance | resource=low RAM)" "balance" "fast balance resource")"
    workers="$(ask_int "CPU workers (0 = auto-detect)" "0" 0 256)"
    pool="$(ask_int "Tunnel links / sessions" "4" 1 1024)"
    health="$(ask_port "Health/stats port (local only, != tunnel port)" "9090")"

    echo -e "  Encryption: ${C_G}1)${C_RESET} chacha20-poly1305 (fast on ARM/mobile)   ${C_G}2)${C_RESET} aes-256-gcm (fast with AES-NI)"
    [ "$(ask_choice "Select" "1" 2)" = "2" ] && cipher="aes-256-gcm" || cipher="chacha20-poly1305"
    echo -e "  ${C_G}Encryption is automatic${C_RESET} (ephemeral X25519 — no key to share)."
    echo -e "  ${C_Y}Security:${C_RESET} restrict the tunnel port (${tunnel_port}) to the peer's IP in your firewall."

    if [ "$engine" = "tun" ]; then
        echo; echo -e "  ${C_C}TUN creates a private virtual network (default 10.10.10.0/24) between the"
        echo -e "  two servers: Iran uses 10.10.10.1, Foreign uses 10.10.10.2. TCP, UDP, ICMP and"
        echo -e "  IPv6 ICMP traffic all flow through it via the assigned tunnel IPs.${C_RESET}"
        iface="$(ask_name "Tunnel interface name" "emergency-tun")"
        local def_ip def_peer
        if [ "$role" = "iran" ]; then def_ip="10.10.10.1/24"; def_peer="10.10.10.2"
        else def_ip="10.10.10.2/24"; def_peer="10.10.10.1"; fi
        tun_ip="$(ask_ipcidr "This host's tunnel IP (CIDR)" "$def_ip")"
        # Peer tunnel IP must be inside the same subnet and differ from ours.
        while true; do
            peer_tun_ip="$(ask "Peer's tunnel IP" "$def_peer")"
            if valid_ipv4 "$peer_tun_ip" && [ "$peer_tun_ip" != "${tun_ip%/*}" ]; then break; fi
            echo -e "  ${C_R}Enter a valid IP in the tunnel subnet, different from ${tun_ip%/*}.${C_RESET}"
        done
    else
        # mux: VPN/listen ports live only on the Iran (entry) side.
        if [ "$role" = "iran" ]; then
            echo; echo -e "  ${C_BOLD}VPN configuration / data port(s)${C_RESET}"
            echo -e "  ${C_C}This is your VPN configuration/data port. Users will connect through this port."
            echo -e "  Common choices are ports like 443.${C_RESET}"
            echo -e "  Formats: ${C_C}443${C_RESET}  ${C_C}443,8443${C_RESET}  ${C_C}200-300${C_RESET}  ${C_C}8000=9000${C_RESET}  (append ${C_C}@pp${C_RESET} for PROXY protocol)"
            local flist
            while true; do
                flist="$(ask_req "VPN data port(s)" "443")"
                forwards_toml="$(csv_to_toml_array "$flist")"
                [ "$forwards_toml" != "[]" ] && break
                echo -e "  ${C_R}At least one VPN/listen port is required.${C_RESET}"
            done
            yesno "Enable PROXY protocol v2 by default?" "n" && proxy="true"
        fi
    fi

    write_config "$name" "$role" "$engine" "$transport" "$mode" "$peer" "$tunnel_port" \
        "$tun_mode" "$tun_ip" "$peer_tun_ip" "$iface" "$mtu" "$workers" "$pool" "$cipher" \
        "$health" "$profile" "$proxy" "$forwards_toml"

    echo; echo -e "  ${C_C}Validating configuration...${C_RESET}"
    if ! "$CORE" validate --config "${CONF_DIR}/${name}.toml"; then
        echo -e "  ${C_R}Validation failed. Config saved but not started.${C_RESET}"; pause; return
    fi

    systemctl enable --now "${SVC_PREFIX}${name}" >/dev/null 2>&1
    sleep 1
    if systemctl is-active --quiet "${SVC_PREFIX}${name}"; then
        echo -e "  ${C_G}✓ Tunnel '${name}' is active.${C_RESET}"
    else
        echo -e "  ${C_R}✗ Tunnel failed to start. Check logs (menu 6).${C_RESET}"
        systemctl --no-pager status "${SVC_PREFIX}${name}" | sed -n '1,6p'
    fi
    pause
}

csv_to_toml_array() { # "a,b,c" -> ["a", "b", "c"]
    local in="$1" out="" tok
    IFS=',' read -r -a parts <<< "$in"
    for tok in "${parts[@]}"; do
        tok="$(echo "$tok" | tr -d '[:space:]')"; [ -z "$tok" ] && continue
        out="${out:+$out, }\"${tok}\""
    done
    echo "[${out}]"
}

write_config() {
    local name="$1" role="$2" engine="$3" transport="$4" mode="$5" peer="$6" tunnel="$7" \
          tun_mode="$8" tun_ip="$9" peer_tun_ip="${10}" iface="${11}" mtu="${12}" workers="${13}" \
          pool="${14}" cipher="${15}" health="${16}" profile="${17}" proxy="${18}" forwards="${19}"
    install -d -m 0750 "$CONF_DIR"
    umask 077
    {
        echo "# Emergency Tunnel configuration"
        echo "name = \"$name\""
        echo "role = \"$role\""
        echo "engine = \"$engine\""
        echo "transport = \"$transport\""
        echo "mode = \"$mode\""
        [ -n "$peer" ] && echo "peer = \"$peer\""
        echo "tunnel_port = $tunnel"
        echo "mtu = $mtu"
        echo "workers = $workers"
        echo "pool = $pool"
        echo "cipher = \"$cipher\""
        echo "health_port = $health"
        echo "profile = \"$profile\""
        echo "log_level = \"info\""
        echo "heartbeat_interval = 10"
        echo "heartbeat_timeout = 25"
        if [ "$engine" = "tun" ]; then
            echo "tun_mode = \"$tun_mode\""
            echo "tun_iface = \"$iface\""
            [ -n "$tun_ip" ]      && echo "tun_ip = \"$tun_ip\""
            [ -n "$peer_tun_ip" ] && echo "peer_tun_ip = \"$peer_tun_ip\""
        else
            echo "proxy_protocol = $proxy"
            echo "forwards = $forwards"
        fi
    } > "${CONF_DIR}/${name}.toml"
    chmod 0600 "${CONF_DIR}/${name}.toml"
}

# --- Manage single tunnel ----------------------------------------------------
pick_tunnel() {
    local ts=(); mapfile -t ts < <(list_tunnels)
    if [ "${#ts[@]}" -eq 0 ]; then echo -e "  ${C_Y}No tunnels configured.${C_RESET}" >&2; return 1; fi
    echo -e "  Select a tunnel:" >&2
    local i; for i in "${!ts[@]}"; do echo -e "    ${C_G}$((i+1)))${C_RESET} ${ts[$i]}" >&2; done
    local ch; read -r -p "$(echo -e "  Choice: ")" ch
    local idx=$((ch-1))
    [ "$idx" -ge 0 ] 2>/dev/null && [ -n "${ts[$idx]:-}" ] || { echo -e "  ${C_R}Invalid.${C_RESET}" >&2; return 1; }
    echo "${ts[$idx]}"
}

svc_action() { # verb
    local verb="$1" name; banner
    name="$(pick_tunnel)" || { pause; return; }
    systemctl "$verb" "${SVC_PREFIX}${name}"
    echo -e "  ${C_G}${verb} -> ${name}${C_RESET}"
    pause
}

show_status() {
    banner; local name; name="$(pick_tunnel)" || { pause; return; }
    systemctl --no-pager status "${SVC_PREFIX}${name}" | sed -n '1,12p'
    if have curl; then
        local hp; hp="$(grep -E '^health_port' "${CONF_DIR}/${name}.toml" | grep -o '[0-9]*')"
        [ -n "$hp" ] && echo -e "\n  ${C_BOLD}Live stats:${C_RESET}" && curl -fsS --max-time 2 "http://127.0.0.1:${hp}/stats" 2>/dev/null | sed 's/^/    /'
    fi
    pause
}

view_logs() {
    banner; local name; name="$(pick_tunnel)" || { pause; return; }
    echo -e "  ${C_C}Live logs for ${name} (Ctrl-C to return)${C_RESET}\n"
    ( trap 'exit 0' INT
      journalctl -u "${SVC_PREFIX}${name}" -n 100 -f 2>/dev/null \
        || tail -n 100 -f "${LOG_DIR}/${name}.log" )
    pause
}

edit_config() {
    banner; local name; name="$(pick_tunnel)" || { pause; return; }
    "${EDITOR:-nano}" "${CONF_DIR}/${name}.toml"
    if "$CORE" validate --config "${CONF_DIR}/${name}.toml"; then
        yesno "Restart tunnel to apply changes?" "y" && systemctl restart "${SVC_PREFIX}${name}"
    else
        echo -e "  ${C_R}Config invalid — not restarted.${C_RESET}"
    fi
    pause
}

delete_tunnel() {
    banner; local name; name="$(pick_tunnel)" || { pause; return; }
    yesno "Really delete '${name}'?" "n" || { pause; return; }
    systemctl disable --now "${SVC_PREFIX}${name}" >/dev/null 2>&1
    rm -f "${CONF_DIR}/${name}.toml" "${LOG_DIR}/${name}.log" "${LOG_DIR}/${name}.log.1"
    systemctl reset-failed "${SVC_PREFIX}${name}" 2>/dev/null || true
    echo -e "  ${C_R}Deleted ${name}.${C_RESET}"
    pause
}

update_core() {
    banner
    echo -e "  ${C_BOLD}Update Core${C_RESET}\n"
    local url="https://raw.githubusercontent.com/AMirHossein-donyavii/tunnel/main/scripts/install.sh"
    [ -f /usr/local/lib/emergency-tunnel/UPDATE_URL ] && url="$(cat /usr/local/lib/emergency-tunnel/UPDATE_URL)"
    local cur; cur="$(core_version)"
    echo -e "  Installed core: ${C_G}v${cur}${C_RESET}"
    echo -e "  Update source:  ${C_C}${url}${C_RESET}"
    echo -e "  (the installer verifies checksums and restarts active tunnels)"
    yesno "Proceed with update?" "n" || { pause; return; }
    if have curl; then
        curl -fsSL "${url}" | bash || echo -e "  ${C_R}Update failed.${C_RESET}"
    else
        echo -e "  ${C_R}curl not available.${C_RESET}"
    fi
    pause
}

system_info() {
    banner
    echo -e "  ${C_BOLD}System Information${C_RESET}\n"
    "$CORE" sysinfo 2>/dev/null | sed 's/^/  /'
    echo
    echo -e "  ${C_BOLD}Kernel:${C_RESET}  $(uname -sr)"
    echo -e "  ${C_BOLD}Uptime:${C_RESET}  $(uptime -p 2>/dev/null || uptime)"
    echo -e "  ${C_BOLD}Memory:${C_RESET}  $(free -h 2>/dev/null | awk '/Mem:/{print $3" / "$2}')"
    echo -e "  ${C_BOLD}Load:${C_RESET}    $(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)"
    echo
    echo -e "  ${C_BOLD}Transports:${C_RESET}"
    "$CORE" transports | sed 's/^/    /'
    pause
}

run_uninstall() {
    banner
    echo -e "  ${C_R}${C_BOLD}Uninstall Emergency Tunnel${C_RESET}\n"
    yesno "This removes the core and all tunnels. Continue?" "n" || { pause; return; }
    for cand in "/usr/local/lib/emergency-tunnel/uninstall.sh" "./uninstall.sh" "./scripts/uninstall.sh"; do
        [ -f "$cand" ] && { bash "$cand"; exit 0; }
    done
    # Inline fallback.
    local t; while IFS= read -r t; do systemctl disable --now "${SVC_PREFIX}${t}" 2>/dev/null; done < <(list_tunnels)
    rm -f /etc/systemd/system/emergency-tunnel@.service /usr/local/bin/et-core /usr/local/bin/et
    systemctl daemon-reload
    yesno "Delete configs and logs too?" "n" && rm -rf "$CONF_DIR" "$LOG_DIR"
    echo -e "  ${C_G}Uninstalled.${C_RESET}"; exit 0
}

main_menu() {
    while true; do
        banner
        echo -e "  ${C_G} 1)${C_RESET} Create tunnel        ${C_G} 6)${C_RESET} View logs"
        echo -e "  ${C_G} 2)${C_RESET} Delete tunnel        ${C_G} 7)${C_RESET} Edit configuration"
        echo -e "  ${C_G} 3)${C_RESET} Restart tunnel       ${C_G} 8)${C_RESET} Update core"
        echo -e "  ${C_G} 4)${C_RESET} Stop tunnel          ${C_G} 9)${C_RESET} System information"
        echo -e "  ${C_G} 5)${C_RESET} Show tunnel status   ${C_G}10)${C_RESET} Uninstall"
        echo -e "  ${C_R} 0)${C_RESET} Exit"
        echo -e "${C_B}${LINE}${C_RESET}"
        local ch; read -r -p "  Select an option: " ch
        case "$ch" in
            1) create_tunnel ;;
            2) delete_tunnel ;;
            3) svc_action restart ;;
            4) svc_action stop ;;
            5) show_status ;;
            6) view_logs ;;
            7) edit_config ;;
            8) update_core ;;
            9) system_info ;;
            10) run_uninstall ;;
            0) clear; exit 0 ;;
            *) echo -e "  ${C_R}Invalid option.${C_RESET}"; sleep 1 ;;
        esac
    done
}

need_root
[ -x "$CORE" ] || echo -e "${C_Y}Warning: core not found at ${CORE}. Some actions will fail.${C_RESET}"
main_menu
