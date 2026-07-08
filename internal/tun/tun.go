// Package tun manages a multi-queue TUN device for the L3 tunnel engine.
//
// A TUN device carries raw IP packets. Opening it with multiple queues lets
// independent worker goroutines read/write in parallel; the kernel distributes
// flows across queues (RSS-style), which preserves per-flow ordering while
// spreading load across CPU cores — the pengutunnel multi-queue model.
package tun

import "os"

// Config describes the interface to create.
type Config struct {
	Name     string // desired interface name, e.g. "emergency-tun"
	Address  string // IPv4 CIDR to assign, e.g. "10.10.10.1/24"
	Address6 string // optional IPv6 CIDR to assign, e.g. "fd00::1/64"
	MTU      int
	Queues   int // number of parallel queues (>=1)
}

// Device is an opened multi-queue TUN interface.
type Device struct {
	name   string
	mtu    int
	queues []*os.File
}

// Name returns the actual interface name assigned by the kernel.
func (d *Device) Name() string { return d.name }

// MTU returns the configured MTU.
func (d *Device) MTU() int { return d.mtu }

// Queues returns the per-queue file handles. Each is safe for one reader and
// one writer goroutine.
func (d *Device) Queues() []*os.File { return d.queues }

// Close tears down all queues (and thus the interface).
func (d *Device) Close() error {
	var first error
	for _, q := range d.queues {
		if err := q.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
