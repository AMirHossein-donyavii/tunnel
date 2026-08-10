//go:build linux

package nettune

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Advise inspects the host's network sysctls and returns human-readable
// suggestions for settings the tunnel cannot set per-socket but that materially
// affect it.
//
// Nothing here is applied automatically: these are host-wide knobs that affect
// every service on the box, so the operator decides. The tunnel runs correctly
// without any of them — it just leaves throughput or latency on the table.
func Advise() []string {
	var out []string

	if cc := readSysctl("net/ipv4/tcp_congestion_control"); cc != "" && cc != "bbr" {
		if strings.Contains(readSysctl("net/ipv4/tcp_available_congestion_control"), "bbr") {
			out = append(out, fmt.Sprintf(
				"congestion control is %q — BBR recovers far better from the loss and reordering typical of long-haul paths: sysctl -w net.ipv4.tcp_congestion_control=bbr", cc))
		}
	}
	if qd := readSysctl("net/core/default_qdisc"); qd != "" && qd != "fq" && qd != "fq_codel" {
		out = append(out, fmt.Sprintf(
			"default qdisc is %q — fq paces BBR properly and keeps the NIC queue short: sysctl -w net.core.default_qdisc=fq", qd))
	}
	// tcp_rmem/wmem max govern how far autotuning may grow a socket buffer. On a
	// high bandwidth-delay-product path (Iran<->Europe is ~100 ms RTT, so 100 Mbit
	// needs ~1.2 MB in flight) a small ceiling caps single-link throughput no
	// matter what the tunnel does.
	if max := lastField(readSysctl("net/ipv4/tcp_rmem")); max > 0 && max < 4<<20 {
		out = append(out, fmt.Sprintf(
			"net.ipv4.tcp_rmem max is %d bytes — too small for a high-latency link; sysctl -w net.ipv4.tcp_rmem='4096 131072 16777216'", max))
	}
	if max := lastField(readSysctl("net/ipv4/tcp_wmem")); max > 0 && max < 4<<20 {
		out = append(out, fmt.Sprintf(
			"net.ipv4.tcp_wmem max is %d bytes — too small for a high-latency link; sysctl -w net.ipv4.tcp_wmem='4096 65536 16777216'", max))
	}
	if v := readSysctl("net/ipv4/tcp_slow_start_after_idle"); v == "1" {
		out = append(out, "net.ipv4.tcp_slow_start_after_idle=1 makes every idle tunnel link restart from a tiny window — the stall you feel after a quiet period; sysctl -w net.ipv4.tcp_slow_start_after_idle=0")
	}
	return out
}

func readSysctl(path string) string {
	b, err := os.ReadFile("/proc/sys/" + path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// lastField parses the final whitespace-separated integer of a sysctl value
// (the "max" of the rmem/wmem triples). It returns 0 when unparseable.
func lastField(s string) int {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0
	}
	n, err := strconv.Atoi(f[len(f)-1])
	if err != nil {
		return 0
	}
	return n
}
