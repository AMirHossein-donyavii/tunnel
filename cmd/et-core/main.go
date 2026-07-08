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
	"github.com/emergency-tunnel/et/internal/sysinfo"
	"github.com/emergency-tunnel/et/internal/transport"

	// Register transports. TCP is production; the rest register experimental
	// placeholders from the transport package's init.
	_ "github.com/emergency-tunnel/et/internal/transport/tcp"
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
	if _, err := config.Load(*cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "invalid: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("ok")
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
  et-core version                print core version
  et-core sysinfo                print CPU/memory limits as JSON
  et-core transports             list available transports
`, core.CoreVersion)
}
