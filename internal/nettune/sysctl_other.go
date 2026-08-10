//go:build !linux

package nettune

// Advise has nothing to suggest off Linux, where the tunnel's host tuning knobs
// do not exist.
func Advise() []string { return nil }
