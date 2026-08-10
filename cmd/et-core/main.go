// Command et-core is the Emergency Tunnel data-plane daemon. It is normally
// launched by systemd (one instance per tunnel) but also exposes helper
// subcommands used by the management panel.
//
// Usage:
//
//	et-core run --config /etc/emergency-tunnel/<name>.toml
//	et-core version
//	et-core sysinfo
//	et-core transports
//	et-core validate --config <file>
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/core"
	"github.com/emergency-tunnel/et/internal/firewall"
	"github.com/emergency-tunnel/et/internal/sysinfo"
	"github.com/emergency-tunnel/et/internal/transport"

	// Register transports. TCP is production; the rest register experimental
	// placeholders from the transport package's init.
	_ "github.com/emergency-tunnel/et/internal/transport/tcp"
	_ "github.com/emergency-tunnel/et/internal/transport/ws"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		cmdRun(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("Core Version    : v%s\n", core.CoreVersion)
	case "sysinfo":
		cmdSysinfo()
	case "transports":
		cmdTransports()
	case "validate":
		cmdValidate(os.Args[2:])
	case "firewall-down":
		cmdFirewallDown(os.Args[2:])
	case "suggest-defaults":
		cmdSuggestDefaults(os.Args[2:])
	case "check-conflicts":
		cmdCheckConflicts(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to tunnel TOML config")
	_ = fs.Parse(args)
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "run: --config is required")
		os.Exit(2)
	}
	if err := core.Run(*cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func cmdValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to tunnel TOML config")
	_ = fs.Parse(args)
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "validate: --config is required")
		os.Exit(2)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid: %v\n", err)
		os.Exit(1)
	}
	// The schema check cannot know which transports this build actually carries,
	// and validate is the ExecStartPre gate — so resolve the transport here too.
	// Without this a config naming an unbuilt transport passed validation and
	// then crash-looped the service at runtime with a much less obvious error.
	if cfg.Engine == config.EngineMux {
		tr, terr := transport.Get(cfg.Transport)
		if terr != nil {
			fmt.Fprintf(os.Stderr, "invalid: %v\n", terr)
			os.Exit(1)
		}
		if tr.Experimental() {
			fmt.Fprintf(os.Stderr, "invalid: transport %q is experimental and not implemented in this build\n", cfg.Transport)
			os.Exit(1)
		}
	}
	fmt.Println("ok")
}

// cmdFirewallDown removes any port-forward rules left by a tunnel. The panel
// calls it on delete as a safety net in case the daemon was killed before it
// could clean up gracefully. It is idempotent (a comment-tag sweep).
func cmdFirewallDown(args []string) {
	fs := flag.NewFlagSet("firewall-down", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to tunnel TOML config")
	_ = fs.Parse(args)
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "firewall-down: --config is required")
		os.Exit(2)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "firewall-down: %v\n", err)
		os.Exit(1)
	}
	firewall.Remove(cfg, nil)
	fmt.Println("ok")
}

// cmdSuggestDefaults prints, as JSON, a set of defaults for a NEW tunnel that
// collide with none of the tunnels already configured on this host. On a fresh
// host it returns the historical defaults unchanged.
func cmdSuggestDefaults(args []string) {
	fs := flag.NewFlagSet("suggest-defaults", flag.ExitOnError)
	dir := fs.String("dir", "/etc/emergency-tunnel", "directory holding tunnel configs")
	role := fs.String("role", config.RoleIran, "role of the new tunnel (iran|kharej)")
	format := fs.String("format", "json", "output format: json | sh (eval-able KEY=value lines)")
	_ = fs.Parse(args)

	s := config.SuggestDefaults(config.ScanDir(*dir), *role)
	if *format == "sh" {
		// Shell-friendly so the panel can `eval` it without a JSON parser.
		fmt.Printf("ET_TUNNEL_PORT=%d\n", s.TunnelPort)
		fmt.Printf("ET_HEALTH_PORT=%d\n", s.HealthPort)
		fmt.Printf("ET_TUN_IFACE=%q\n", s.TunIface)
		fmt.Printf("ET_TUN_IP=%q\n", s.TunIP)
		fmt.Printf("ET_PEER_TUN_IP=%q\n", s.PeerTunIP)
		fmt.Printf("ET_SPOOF_SRC=%q\n", s.SpoofSrcIP)
		fmt.Printf("ET_SPOOF_DST=%q\n", s.SpoofDstIP)
		fmt.Printf("ET_SUBNET=%q\n", s.Subnet)
		fmt.Printf("ET_NAME=%q\n", s.Name)
		return
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	fmt.Println(string(b))
}

// cmdCheckConflicts verifies a candidate config against the other tunnels on this
// host and exits non-zero (listing each clash) if it would take a resource that
// is already in use. The panel runs this at creation time; it is deliberately NOT
// part of `validate`, so an already-installed tunnel can never be blocked from
// starting by a pre-existing overlap.
func cmdCheckConflicts(args []string) {
	fs := flag.NewFlagSet("check-conflicts", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to the candidate tunnel TOML config")
	dir := fs.String("dir", "/etc/emergency-tunnel", "directory holding the existing tunnel configs")
	_ = fs.Parse(args)
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "check-conflicts: --config is required")
		os.Exit(2)
	}
	cand, err := config.LoadRelaxed(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check-conflicts: %v\n", err)
		os.Exit(2)
	}
	conflicts := config.FindConflicts(cand, config.ScanDir(*dir))
	if len(conflicts) == 0 {
		fmt.Println("ok")
		return
	}
	for _, c := range conflicts {
		fmt.Fprintf(os.Stderr, "conflict: %s\n", c)
	}
	os.Exit(1)
}

func cmdSysinfo() {
	out := map[string]any{
		"effective_cpus":     sysinfo.EffectiveCPUs(),
		"memory_limit_bytes": sysinfo.MemoryLimitBytes(),
		"core_version":       core.CoreVersion,
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
}

func cmdTransports() {
	for _, t := range transport.All() {
		status := "ready"
		if t.Experimental() {
			status = "experimental"
		}
		fmt.Printf("%-10s [%-12s] %s\n", t.Name(), status, t.Summary())
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Emergency Tunnel core v%s

Usage:
  et-core run --config <file>    run a tunnel (used by systemd)
  et-core validate --config <f>  validate a config file
  et-core firewall-down --config <f>  remove a tunnel's port-forward rules
  et-core suggest-defaults [--dir D] [--role R]   non-conflicting defaults (JSON)
  et-core check-conflicts --config <f> [--dir D]  clash check vs existing tunnels
  et-core version                print core version
  et-core sysinfo                print CPU/memory limits as JSON
  et-core transports             list available transports
`, core.CoreVersion)
}
