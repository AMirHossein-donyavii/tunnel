//go:build linux

package tun

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux TUN flags (from <linux/if_tun.h>).
const (
	iffTUN        = 0x0001
	iffNoPI       = 0x1000
	iffMultiQueue = 0x0100
	ifnamsiz      = 16
	ifreqSize     = 40 // sizeof(struct ifreq)
)

// Open creates (or attaches to) a multi-queue TUN device and configures its
// address, MTU and up state.
func Open(cfg Config) (*Device, error) {
	if cfg.Queues < 1 {
		cfg.Queues = 1
	}
	flags := uint16(iffTUN | iffNoPI)
	if cfg.Queues > 1 {
		flags |= iffMultiQueue
	}

	d := &Device{mtu: cfg.MTU}
	for i := 0; i < cfg.Queues; i++ {
		f, name, err := createQueue(cfg.Name, flags)
		if err != nil {
			_ = d.Close()
			return nil, fmt.Errorf("tun: create queue %d: %w", i, err)
		}
		d.name = name
		d.queues = append(d.queues, f)
	}

	if err := configure(d.name, cfg.Address, cfg.Address6, cfg.MTU, cfg.Queues); err != nil {
		_ = d.Close()
		return nil, err
	}
	return d, nil
}

func createQueue(name string, flags uint16) (*os.File, string, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var req [ifreqSize]byte
	if len(name) >= ifnamsiz {
		unix.Close(fd)
		return nil, "", fmt.Errorf("interface name too long: %q", name)
	}
	copy(req[:ifnamsiz], name)
	req[ifnamsiz] = byte(flags)
	req[ifnamsiz+1] = byte(flags >> 8)

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req[0]))); errno != 0 {
		unix.Close(fd)
		return nil, "", fmt.Errorf("TUNSETIFF: %w", errno)
	}
	// Put the fd in non-blocking mode so os.NewFile registers it with the Go
	// runtime poller. This lets a blocked Read be interrupted immediately when
	// the fd is Closed (fast, deterministic shutdown) instead of hanging until
	// the next packet arrives.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, "", fmt.Errorf("set nonblock: %w", err)
	}
	real := string(bytes.TrimRight(req[:ifnamsiz], "\x00"))
	return os.NewFile(uintptr(fd), "/dev/net/tun"), real, nil
}

// txQueueLen is the TUN device's kernel queue depth. The default (500 packets,
// ~700 KB) is another place a backlog can build where the tunnel's own
// scheduler cannot see it; a short queue pushes back on the kernel instead and
// leaves the queueing decisions to fq_codel and the engine.
const txQueueLen = 256

// configure assigns the address/MTU and brings the link up using iproute2.
// (Shelling out to `ip` avoids a netlink dependency and matches how the
// reference tools configure their interfaces.)
func configure(name, address, address6 string, mtu, queues int) error {
	steps := [][]string{
		{"ip", "link", "set", "dev", name, "mtu", fmt.Sprintf("%d", mtu)},
		{"ip", "link", "set", "dev", name, "txqueuelen", fmt.Sprintf("%d", txQueueLen)},
		{"ip", "addr", "add", address, "dev", name},
	}
	if address6 != "" {
		steps = append(steps, []string{"ip", "-6", "addr", "add", address6, "dev", name})
	}
	steps = append(steps, []string{"ip", "link", "set", "dev", name, "up"})
	for _, s := range steps {
		cmd := exec.Command(s[0], s[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			// "addr add" is non-fatal if the address already exists (idempotent
			// restarts).
			if isAddrAdd(s) && bytes.Contains(out, []byte("File exists")) {
				continue
			}
			// txqueuelen is a tuning nicety, not a requirement.
			if isTxQueueLen(s) {
				continue
			}
			return fmt.Errorf("tun: %v: %w: %s", s, err, bytes.TrimSpace(out))
		}
	}
	applyQdisc(name, queues)
	return nil
}

// applyQdisc puts fq_codel on the TUN device. The kernel's default pfifo_fast
// is a plain FIFO: one bulk transfer fills it and every other flow queues
// behind that backlog. fq_codel hashes flows into separate queues and applies
// CoDel to each, so a download cannot add delay to an interactive session
// sharing the tunnel. This complements the engine's own scheduler — fq_codel
// gives per-flow fairness on the way into the TUN device, the engine gives
// priority and AQM on the way out to the carrier.
//
// A multi-queue TUN device gets an `mq` root with one child qdisc per queue, so
// the children are replaced individually: that keeps the kernel's queue
// parallelism (and the queue-to-link affinity the engine relies on) while still
// adding AQM. Replacing the root instead would collapse every queue onto one
// qdisc. Single-queue devices have no mq root, so they take the root path.
//
// Best-effort throughout: `tc` may be absent and some kernels are built without
// sch_fq_codel, in which case the tunnel simply runs with the default qdisc.
func applyQdisc(name string, queues int) {
	if queues > 1 {
		ok := true
		for i := 1; i <= queues; i++ {
			if !tcReplace(name, fmt.Sprintf(":%d", i)) {
				ok = false
				break
			}
		}
		if ok {
			return
		}
	}
	tcReplace(name, "root")
}

// tcReplace installs the best available AQM qdisc at the given parent.
func tcReplace(name, parent string) bool {
	args := []string{"qdisc", "replace", "dev", name}
	if parent == "root" {
		args = append(args, "root")
	} else {
		args = append(args, "parent", parent)
	}
	for _, kind := range []string{"fq_codel", "fq"} {
		if exec.Command("tc", append(args, kind)...).Run() == nil {
			return true
		}
	}
	return false
}

func isTxQueueLen(s []string) bool {
	for _, a := range s {
		if a == "txqueuelen" {
			return true
		}
	}
	return false
}

func isAddrAdd(s []string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == "addr" && s[i+1] == "add" {
			return true
		}
	}
	return false
}
