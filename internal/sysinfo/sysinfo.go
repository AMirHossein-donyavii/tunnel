// Package sysinfo discovers CPU and memory limits, honouring cgroup v1/v2
// quotas so the core sizes its worker pool to what the VPS actually grants
// rather than to the physical host.
package sysinfo

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// EffectiveCPUs returns the number of CPUs the process may realistically use,
// clamped to [1, GOMAXPROCS-equivalent]. It respects a cgroup CPU quota when
// one is set (common on containerised / limited VPS plans).
func EffectiveCPUs() int {
	n := runtime.NumCPU()
	if q := cgroupCPUQuota(); q > 0 && q < n {
		n = q
	}
	if n < 1 {
		n = 1
	}
	return n
}

// Workers resolves the configured worker count. 0 means auto (= EffectiveCPUs).
// A manual value is clamped to a sane range.
func Workers(configured int) int {
	if configured <= 0 {
		return EffectiveCPUs()
	}
	if configured > 256 {
		return 256
	}
	return configured
}

// cgroupCPUQuota returns ceil(quota/period) from cgroup v2 then v1, or 0.
func cgroupCPUQuota() int {
	// cgroup v2: /sys/fs/cgroup/cpu.max => "<quota> <period>" or "max <period>"
	if b, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		f := strings.Fields(strings.TrimSpace(string(b)))
		if len(f) == 2 && f[0] != "max" {
			quota, e1 := strconv.Atoi(f[0])
			period, e2 := strconv.Atoi(f[1])
			if e1 == nil && e2 == nil && period > 0 && quota > 0 {
				return ceilDiv(quota, period)
			}
		}
	}
	// cgroup v1
	quota := readInt("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	period := readInt("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if quota > 0 && period > 0 {
		return ceilDiv(quota, period)
	}
	return 0
}

// MemoryLimitBytes returns the cgroup memory limit in bytes, or 0 if unlimited
// / unknown. Used to cap buffer pools on tightly constrained plans.
func MemoryLimitBytes() int64 {
	if b, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil { // v2
		s := strings.TrimSpace(string(b))
		if s != "max" {
			if v, err := strconv.ParseInt(s, 10, 64); err == nil {
				return v
			}
		}
	}
	if v := readInt64("/sys/fs/cgroup/memory/memory.limit_in_bytes"); v > 0 && v < (1<<62) {
		return v
	}
	return 0
}

func readInt(path string) int {
	return int(readInt64(path))
}

func readInt64(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func ceilDiv(a, b int) int {
	if b == 0 {
		return 0
	}
	return (a + b - 1) / b
}
