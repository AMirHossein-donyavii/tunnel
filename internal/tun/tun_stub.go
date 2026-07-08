//go:build !linux

package tun

import "errors"

// Open is unsupported off Linux. The L3 engine is Linux-only (TUN devices);
// this stub exists so the project still compiles for development on other OSes.
func Open(cfg Config) (*Device, error) {
	return nil, errors.New("tun: the L3 engine requires Linux (TUN device unavailable on this OS)")
}
