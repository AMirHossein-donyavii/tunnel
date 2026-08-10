package rudp

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
)

// TestConnThroughput drives the real Conn over a loopback UDP socket and
// reports the ARQ's view, so a throughput problem can be attributed to the
// state machine or to the plumbing around it.
func TestConnThroughput(t *testing.T) {
	tr := &rudpTransport{}
	log := logx.New(io.Discard, logx.ERROR)
	ln, err := tr.NewListener(&config.Config{TunnelPort: 0, Profile: "balance"}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.UDPAddr).Port

	srv := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			srv <- c
		}
	}()

	d, _ := tr.NewDialer(&config.Config{Peer: "127.0.0.1", TunnelPort: port, Profile: "balance"}, log)
	cli, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	s := <-srv
	defer s.Close()

	go func() { io.Copy(io.Discard, s) }()

	buf := make([]byte, 32*1024)
	start := time.Now()
	var sent int64
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, err := cli.Write(buf)
		if err != nil {
			break
		}
		sent += int64(n)
	}
	d2 := time.Since(start).Seconds()
	c := cli.(*Conn)
	cwnd, inflight, queued, srtt, rto := c.arq.Stats()
	t.Logf("throughput %.0f Mbit/s | cwnd=%d inflight=%d queued=%d srtt=%dms rto=%dms",
		float64(sent)*8/d2/1e6, cwnd, inflight, queued, srtt, rto)
	if queued > 5000 {
		t.Logf("NOTE: %d segments backed up in the send queue — the writer is outrunning the wire", queued)
	}
}
