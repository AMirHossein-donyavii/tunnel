package l3

import (
	"net"
	"testing"
	"time"
)

// Every listener must be usable without its constructor having remembered to
// build the handshake queue.
//
// Two of the four did not. The queue was added to each constructor by hand, the
// icmp and spf ones were missed, and nothing failed until a peer connected —
// then AcceptLink dereferenced a nil queue and the process died with SIGSEGV,
// systemd restarted it, and the tunnel crash-looped. The unit tests at the time
// exercised the queue directly, never the listeners, so all of them passed.
//
// This constructs each listener as a zero value — precisely the "constructor
// forgot" case — and requires that accepting and closing still work.
func TestListenersWorkWithoutQueueInTheConstructor(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// The packet listeners are shut down through the channel their accept loop
	// watches rather than Close(), which also closes a socket these synthetic
	// listeners do not have. What is under test is the queue, not the socket.
	udpClosed := make(chan struct{})
	icmpClosed := make(chan struct{})
	spfClosed := make(chan struct{})

	cases := []struct {
		name string
		l    linkListener
		stop func()
	}{
		{"tcp", &tcpLinkListener{l: ln}, func() { ln.Close() }},
		{"udp", &udpLinkListener{accept: make(chan *udpFlow, 1), closed: udpClosed}, func() { close(udpClosed) }},
		{"icmp", &icmpLinkListener{accept: make(chan *icmpFlow, 1), closed: icmpClosed}, func() { close(icmpClosed) }},
		{"spf", &spfLinkListener{accept: make(chan *spfFlow, 1), closed: spfClosed}, func() { close(spfClosed) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan struct{})
			go func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("AcceptLink panicked: %v", r)
					}
					close(done)
				}()
				// Returns an error once the listener closes; the point is that it
				// neither panics nor blocks forever.
				_, _ = tc.l.AcceptLink()
			}()

			time.Sleep(50 * time.Millisecond)
			tc.stop()

			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("AcceptLink did not return after the listener closed")
			}
		})
	}
}
