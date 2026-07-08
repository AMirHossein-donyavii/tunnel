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
	iffTUN         = 0x0001
	iffNoPI        = 0x1000
	iffMultiQueue  = 0x0100
	ifnamsiz       = 16
	ifreqSize      = 40 // sizeof(struct ifreq)
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

	if err := configure(d.name, cfg.Address, cfg.Address6, cfg.MTU); err != nil {
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
	real := string(bytes.TrimRight(req[:ifnamsiz], "\x00"))
	return os.NewFile(uintptr(fd), "/dev/net/tun"), real, nil
}

// configure assigns the address/MTU and brings the link up using iproute2.
// (Shelling out to `ip` avoids a netlink dependency and matches how the
// reference tools configure their interfaces.)
func configure(name, address, address6 string, mtu int) error {
	steps := [][]string{
		{"ip", "link", "set", "dev", name, "mtu", fmt.Sprintf("%d", mtu)},
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
			return fmt.Errorf("tun: %v: %w: %s", s, err, bytes.TrimSpace(out))
		}
	}
	return nil
}

func isAddrAdd(s []string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == "addr" && s[i+1] == "add" {
			return true
		}
	}
	return false
}
