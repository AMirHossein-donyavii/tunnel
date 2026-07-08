// Package logx is a tiny dependency-free structured logger with leveled output
// and size-based file rotation. It is allocation-light on the hot path (stats
// lines) and safe for concurrent use.
package logx

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
)

func ParseLevel(s string) Level {
	switch s {
	case "debug":
		return DEBUG
	case "warn":
		return WARN
	case "error":
		return ERROR
	default:
		return INFO
	}
}

func (l Level) tag() string {
	switch l {
	case DEBUG:
		return "DBG"
	case WARN:
		return "WRN"
	case ERROR:
		return "ERR"
	default:
		return "INF"
	}
}

// Logger writes leveled lines to an io.Writer. The zero value is unusable; use New.
type Logger struct {
	mu    sync.Mutex
	w     io.Writer
	min   Level
	clock func() time.Time
}

// New returns a Logger. If w is nil it writes to stderr.
func New(w io.Writer, min Level) *Logger {
	if w == nil {
		w = os.Stderr
	}
	return &Logger{w: w, min: min, clock: time.Now}
}

func (l *Logger) log(lv Level, format string, args ...any) {
	if lv < l.min {
		return
	}
	ts := l.clock().UTC().Format("2006-01-02T15:04:05.000Z")
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}
	l.mu.Lock()
	fmt.Fprintf(l.w, "%s %s %s\n", ts, lv.tag(), msg)
	l.mu.Unlock()
}

func (l *Logger) Debug(f string, a ...any) { l.log(DEBUG, f, a...) }
func (l *Logger) Info(f string, a ...any)  { l.log(INFO, f, a...) }
func (l *Logger) Warn(f string, a ...any)  { l.log(WARN, f, a...) }
func (l *Logger) Error(f string, a ...any) { l.log(ERROR, f, a...) }

// RotatingFile is an io.Writer that rotates a log file once it exceeds maxBytes,
// keeping a single ".1" backup. Suitable when running outside journald.
type RotatingFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	size     int64
	f        *os.File
}

// NewRotatingFile opens (creating dirs as needed) the log file for appending.
func NewRotatingFile(path string, maxBytes int64) (*RotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	st, _ := f.Stat()
	var sz int64
	if st != nil {
		sz = st.Size()
	}
	return &RotatingFile{path: path, maxBytes: maxBytes, size: sz, f: f}, nil
}

func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.maxBytes > 0 && r.size+int64(len(p)) > r.maxBytes {
		r.rotate()
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *RotatingFile) rotate() {
	_ = r.f.Close()
	_ = os.Rename(r.path, r.path+".1")
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		// Fall back to stderr if reopening fails; never crash the tunnel on a log error.
		r.f = os.Stderr
		return
	}
	r.f = f
	r.size = 0
}

func (r *RotatingFile) Close() error { return r.f.Close() }
