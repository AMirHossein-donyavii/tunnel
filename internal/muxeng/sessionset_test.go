package muxeng

import (
	"net"
	"testing"

	"github.com/emergency-tunnel/et/internal/mux"
)

// TestSessionSetCountTransitions verifies the REAL add/remove report the live
// count so serveSession logs exactly one "connected" (0->1) and one
// "disconnected" (1->0) transition without a separate racy count() call.
func TestSessionSetCountTransitions(t *testing.T) {
	var s sessionSet
	mk := func() *mux.Session {
		c1, _ := net.Pipe()
		return mux.Client(c1, mux.Config{}) // keepalive disabled (zero interval)
	}
	a, b := mk(), mk()
	defer a.Close()
	defer b.Close()

	if n := s.add(a); n != 1 {
		t.Fatalf("first add -> %d, want 1 (0->1 transition fires the connected log)", n)
	}
	if n := s.add(b); n != 2 {
		t.Fatalf("second add -> %d, want 2 (no extra connected log)", n)
	}
	if n := s.remove(a); n != 1 {
		t.Fatalf("remove one -> %d, want 1 (no disconnected log yet)", n)
	}
	if n := s.remove(b); n != 0 {
		t.Fatalf("last remove -> %d, want 0 (1->0 transition fires the disconnected log)", n)
	}
}
