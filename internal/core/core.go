// Package core wires configuration, logging, the health endpoint and the
// forwarding engine into a single runnable tunnel daemon.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/l3"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/muxeng"
	"github.com/emergency-tunnel/et/internal/sysinfo"
)

// CoreVersion is the tunnel core version, surfaced to the panel via
// `et-core version`. It is a var (not a const) so release builds can stamp the
// exact version with: -ldflags "-X .../internal/core.CoreVersion=1.2.3".
var CoreVersion = "1.9.0"

// LogDir is where per-tunnel logs are written when not attached to journald.
const LogDir = "/var/log/emergency-tunnel"

// Run loads the config at path and runs the tunnel until a termination signal.
func Run(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}

	// Sizing: honour cgroup CPU limits so we do not spin up more OS threads
	// than the plan grants. This is central to the low-CPU/low-RAM goal.
	workers := sysinfo.Workers(cfg.Workers)
	runtime.GOMAXPROCS(workers)
	tuneGC(cfg.Profile)

	log, closeLog := newLogger(cfg)
	defer closeLog()

	log.Info("emergency-tunnel core %s starting tunnel %q", CoreVersion, cfg.Name)
	log.Info("resources: workers=%d gomaxprocs=%d effective_cpus=%d profile=%s",
		workers, runtime.GOMAXPROCS(0), sysinfo.EffectiveCPUs(), cfg.Profile)

	// Select the data plane: mux = TCP Reverse Tunnel; tun/spf = virtual interface.
	var eng engine
	switch {
	case cfg.UsesL3(): // TUN or SPF — both use the L3 data plane
		eng, err = l3.New(cfg, log)
	case cfg.Engine == config.EngineMux:
		eng, err = muxeng.New(cfg, log)
	default:
		return fmt.Errorf("unknown engine %q", cfg.Engine)
	}
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.HealthPort > 0 {
		go serveHealth(ctx, cfg, eng, log)
	}

	// Last-resort auto-recovery for long-running stability: if the tunnel comes
	// up and later stays down past the recovery window, exit so systemd restarts
	// from a clean slate. It never fires before the tunnel has been healthy at
	// least once, so an unreachable peer can't cause a restart loop.
	go watchdog(ctx, eng, log)

	// Run the engine; on a termination signal, give it a brief window to clean
	// up and then force-exit so stop/restart/delete are always fast.
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		select {
		case err = <-done:
		case <-time.After(3 * time.Second):
			log.Warn("shutdown exceeded 3s — forcing exit")
			os.Exit(0)
		}
	}
	log.Info("tunnel %q stopped", cfg.Name)
	return err
}

// engine is the common interface implemented by the mux and tun engines.
type engine interface {
	Run(context.Context) error
	Snapshot() any
	// Healthy reports whether the tunnel currently has at least one live link.
	Healthy() bool
}

// RecoveryTimeout is how long the tunnel may stay down (after having been up)
// before the watchdog forces a restart. It is well above a normal reconnect
// (heartbeat/keepalive cycle a dead link within ~25s), so it only ever catches
// a genuine wedge; during a real peer outage it merely restarts every ~2 min,
// which is benign and stays under systemd's start-rate limit.
const RecoveryTimeout = 120 * time.Second

// watchdog exits the process if the tunnel wedges (up, then down past the
// recovery window). systemd's Restart=always then brings it back cleanly.
func watchdog(ctx context.Context, eng engine, log *logx.Logger) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	everUp := false
	var downSince time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if eng.Healthy() {
				everUp = true
				downSince = time.Time{}
				continue
			}
			if !everUp {
				continue // never came up yet: keep waiting, don't restart-loop
			}
			if downSince.IsZero() {
				downSince = time.Now()
				continue
			}
			if time.Since(downSince) >= RecoveryTimeout {
				log.Error("tunnel down for %s after being healthy — exiting for a clean restart", RecoveryTimeout)
				os.Exit(1)
			}
		}
	}
}

// newLogger returns a logger writing to both the per-tunnel rotating file and
// stderr (captured by journald), plus a closer.
func newLogger(cfg *config.Config) (*logx.Logger, func()) {
	level := logx.ParseLevel(cfg.LogLevel)
	rf, err := logx.NewRotatingFile(fmt.Sprintf("%s/%s.log", LogDir, cfg.Name), 10*1024*1024)
	if err != nil {
		// Fall back to stderr only.
		return logx.New(os.Stderr, level), func() {}
	}
	mw := multiWriter{rf, os.Stderr}
	return logx.New(mw, level), func() { _ = rf.Close() }
}

type multiWriter []interface{ Write([]byte) (int, error) }

func (m multiWriter) Write(p []byte) (int, error) {
	for _, w := range m {
		_, _ = w.Write(p)
	}
	return len(p), nil
}

// tuneGC trades a little memory for fewer GC cycles on the fast profile, and the
// reverse on the resource profile, keeping RAM low on constrained VPS plans.
func tuneGC(profile string) {
	switch profile {
	case config.ProfileFast:
		debug.SetGCPercent(200)
	case config.ProfileResource:
		debug.SetGCPercent(50)
		if lim := sysinfo.MemoryLimitBytes(); lim > 0 {
			// Leave headroom; soft-cap the Go heap under the cgroup limit.
			debug.SetMemoryLimit(int64(float64(lim) * 0.85))
		}
	default: // balance
		debug.SetGCPercent(100)
		if lim := sysinfo.MemoryLimitBytes(); lim > 0 {
			debug.SetMemoryLimit(int64(float64(lim) * 0.90))
		}
	}
}

// serveHealth exposes a localhost-only health/stats endpoint.
func serveHealth(ctx context.Context, cfg *config.Config, eng engine, log *logx.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		s := eng.Snapshot()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":      cfg.Name,
			"role":      cfg.Role,
			"engine":    cfg.Engine,
			"transport": cfg.Transport,
			"stats":     s,
		})
	})
	srv := &http.Server{
		Addr:         net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", cfg.HealthPort)),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Warn("health server: %v", err)
	}
}
