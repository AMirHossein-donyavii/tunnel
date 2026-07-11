package l3

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestIsTransientReadErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"closed", net.ErrClosed, false},
		{"wrapped-closed", fmt.Errorf("read: %w", net.ErrClosed), false},
		{"enobufs", syscall.ENOBUFS, true},
		{"wrapped-enobufs", fmt.Errorf("recv: %w", syscall.ENOBUFS), true},
		{"eintr", syscall.EINTR, true},
		{"eagain", syscall.EAGAIN, true},
		{"generic", errors.New("boom"), false},
	}
	for _, c := range cases {
		if got := isTransientReadErr(c.err); got != c.want {
			t.Errorf("%s: isTransientReadErr=%v want %v", c.name, got, c.want)
		}
	}
}

func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// TestDeadlineGateInterruptsBlockedRead is the core of the long-run fix: a read
// already blocked with NO deadline must unblock the instant a deadline is set in
// the past (what the pump does to tear down a stalled reader on link cycle). The
// old hand-rolled version captured the deadline at entry and hung forever.
func TestDeadlineGateInterruptsBlockedRead(t *testing.T) {
	var g deadlineGate
	in := make(chan []byte)
	closed := make(chan struct{})
	res := make(chan error, 1)
	go func() { _, err := g.wait(in, closed); res <- err }()

	time.Sleep(30 * time.Millisecond) // ensure the read is parked
	g.set(time.Now().Add(-time.Second))

	select {
	case err := <-res:
		if !isTimeoutErr(err) {
			t.Fatalf("expected timeout error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked read did not wake on deadline change — the hang bug is back")
	}
}

func TestDeadlineGateDataWins(t *testing.T) {
	var g deadlineGate
	in := make(chan []byte, 1)
	in <- []byte("payload")
	pkt, err := g.wait(in, make(chan struct{}))
	if err != nil || string(pkt) != "payload" {
		t.Fatalf("want payload,nil; got %q,%v", pkt, err)
	}
}

func TestDeadlineGateCloseWins(t *testing.T) {
	var g deadlineGate
	closed := make(chan struct{})
	close(closed)
	_, err := g.wait(make(chan []byte), closed)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("want net.ErrClosed, got %v", err)
	}
}

// TestDeadlineGateFutureDeadlineThenData verifies a pending deadline does not
// pre-empt data that arrives first, and the timer is cleaned up.
func TestDeadlineGateFutureDeadlineThenData(t *testing.T) {
	var g deadlineGate
	g.set(time.Now().Add(time.Hour))
	in := make(chan []byte, 1)
	in <- []byte("ok")
	pkt, err := g.wait(in, make(chan struct{}))
	if err != nil || string(pkt) != "ok" {
		t.Fatalf("want ok,nil; got %q,%v", pkt, err)
	}
}
