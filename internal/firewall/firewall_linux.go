//go:build linux

package firewall

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/emergency-tunnel/et/internal/config"
)

// Logger is the subset of the daemon logger used here; nil is accepted (silent).
type Logger interface {
	Info(string, ...any)
	Warn(string, ...any)
}

// iptables is a resolved pair of binaries plus the lock-wait flag shared by all
// mutating calls so concurrent tunnels don't race the xtables lock.
type iptables struct {
	bin  string // iptables
	save string // iptables-save (may be "" if absent)
}

// Apply installs the tunnel's port-forward rules on iface. It is idempotent:
// any previous rules bearing this tunnel's tag are swept first (so a restart or
// an edited port set never leaves stale or duplicate rules), then the current
// set is (re)added. A missing iptables or a failed rule is reported to the
// caller but is non-fatal to the tunnel — the data plane runs regardless.
func Apply(cfg *config.Config, iface string, log Logger) error {
	rules, err := Plan(cfg)
	if err != nil {
		return err
	}
	needRST := SPFNeedsRSTDrop(cfg)
	if len(rules) == 0 && !needRST {
		return nil
	}
	ipt, err := locate()
	if err != nil {
		return err
	}
	if len(rules) > 0 {
		enableForwarding(log) // global sysctl; best-effort (panel persists it)
	}

	tag := Tag(cfg.Name)
	ipt.sweep(tag) // clear any prior/duplicate rules for this tunnel

	all := make([]iptRule, 0, len(rules)*4+3)
	for _, r := range rules {
		all = append(all, rulesFor(r, iface, tag)...)
	}
	if len(rules) > 0 {
		// One MSS clamp per tunnel guards TCP forwards against MTU blackholing.
		all = append(all, mssClampRule(iface, tag))
	}
	if needRST {
		all = append(all, spfRSTRules(cfg.TunnelPort, tag)...)
	}
	for _, ir := range all {
		if err := ipt.add(ir); err != nil {
			ipt.sweep(tag) // roll back the partial set
			return fmt.Errorf("apply %s/%s: %w", ir.table, ir.chain, err)
		}
	}
	if log != nil {
		if len(rules) > 0 {
			log.Info("Port forwarding enabled: %d rule(s) -> %s via %s (mss clamped to path mtu)", len(rules), cfg.PeerTunIP, iface)
		}
		if needRST {
			log.Info("SPF tcp: suppressing the kernel's resets on port %d (the carrier's segments belong to no socket)", cfg.TunnelPort)
		}
	}
	return nil
}

// Remove deletes every rule this tunnel owns. It works purely from the tunnel
// name (a comment sweep), so it is safe to call after an ungraceful kill when
// the applying process — and its iface — are already gone.
func Remove(cfg *config.Config, log Logger) {
	if !Enabled(cfg) && !SPFNeedsRSTDrop(cfg) {
		return
	}
	ipt, err := locate()
	if err != nil {
		return
	}
	if n := ipt.sweep(Tag(cfg.Name)); n > 0 && log != nil {
		log.Info("Firewall rules removed: %d", n)
	}
}

// add installs one rule unless an identical one already exists (-C guard), so a
// double apply can never duplicate a rule.
func (i iptables) add(r iptRule) error {
	check := append([]string{"-t", r.table, "-C", r.chain}, r.args...)
	if i.run(check...) == nil {
		return nil // already present
	}
	add := append([]string{"-t", r.table, "-A", r.chain}, r.args...)
	return i.run(add...)
}

// sweep deletes every rule in the nat and filter tables carrying tag. It reads
// the current rule set with iptables-save and issues a -D for each matching
// line, so it removes duplicates and orphans regardless of how they arose.
// Returns the number of rules deleted.
func (i iptables) sweep(tag string) int {
	if i.save == "" {
		return 0
	}
	deleted := 0
	for _, table := range []string{"nat", "filter", "mangle"} {
		out, err := exec.Command(i.save, "-t", table).Output()
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(out))
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if !strings.HasPrefix(line, "-A ") || !strings.Contains(line, tag) {
				continue
			}
			toks := tokenize(line)
			if len(toks) < 2 {
				continue
			}
			toks[0] = "-D" // "-A CHAIN ..." -> "-D CHAIN ..."
			del := append([]string{"-t", table}, toks...)
			if i.run(del...) == nil {
				deleted++
			}
		}
	}
	return deleted
}

// run executes `iptables -w 5 <args...>`, returning any error with its output.
func (i iptables) run(args ...string) error {
	full := append([]string{"-w", "5"}, args...)
	cmd := exec.Command(i.bin, full...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %v", i.bin, strings.Join(full, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

// enableForwarding turns on IPv4 forwarding. Best-effort: under the systemd
// sandbox (ProtectKernelTunables) this write is denied, in which case the panel
// has already set and persisted it globally, so a failure here is not an error.
func enableForwarding(log Logger) {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil && log != nil {
		log.Warn("could not set net.ipv4.ip_forward (ensure it is enabled): %v", err)
	}
}

// locate resolves the iptables and iptables-save binaries from PATH or the
// standard sbin locations.
func locate() (iptables, error) {
	bin := findBin("iptables", "/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables")
	if bin == "" {
		return iptables{}, fmt.Errorf("iptables binary not found (install iptables for port forwarding)")
	}
	save := findBin("iptables-save", "/usr/sbin/iptables-save", "/sbin/iptables-save", "/usr/bin/iptables-save")
	return iptables{bin: bin, save: save}, nil
}

func findBin(name string, fallbacks ...string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, p := range fallbacks {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// tokenize splits an iptables-save line on spaces, keeping double-quoted spans
// (e.g. the comment) as a single token with the quotes stripped.
func tokenize(line string) []string {
	var toks []string
	var b strings.Builder
	inQ := false
	flush := func() {
		if b.Len() > 0 {
			toks = append(toks, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQ = !inQ
		case c == ' ' && !inQ:
			flush()
		default:
			b.WriteByte(c)
		}
	}
	flush()
	return toks
}
