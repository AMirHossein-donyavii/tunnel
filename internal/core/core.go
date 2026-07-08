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
	"github.com/emergency-tunnel/et/internal/forward"
	"github.com/emergency-tunnel/et/internal/l3"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/muxeng"
	"github.com/emergency-tunnel/et/internal/sysinfo"
)

// CoreVersion is the tunnel core version, surfaced to the panel via
// `et-core version`. It is a var (not a const) so release builds can stamp the
// exact version with: -ldflags "-X .../internal/core.CoreVersion=1.2.3".
var CoreVersion = "1.2.1"

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

	// Select the data plane. L3 is the TUN tunnel; L4 is the port-forwarder.
	var eng engine
	switch cfg.Engine {
	case config.EngineL3:
		eng, err = l3.New(cfg, log)
	case config.EngineMux:
		eng, err = muxeng.New(cfg, log)
	default:
		eng, err = forward.New(cfg, log)
	}
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.HealthPort > 0 {
		go serveHealth(ctx, cfg, eng, log)
	}

	err = eng.Run(ctx)
	log.Info("tunnel %q stopped", cfg.Name)
	return err
}

// engine is the common interface implemented by both the l3 and l4 engines.
type engine interface {
	Run(context.Context) error
	Snapshot() any
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
