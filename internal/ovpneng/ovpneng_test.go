package ovpneng

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/crypto"
	"github.com/emergency-tunnel/et/internal/logx"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	return &Engine{cfg: &config.Config{}, log: logx.New(io.Discard, logx.ERROR)}
}

// The relay is the whole data path, so it must move bytes exactly, in both
// directions, at sizes either side of its buffer.
func TestRelayCarriesBothDirectionsExactly(t *testing.T) {
	vpnLocal, vpnRemote := net.Pipe()
	linkLocal, linkRemote := net.Pipe()
	defer vpnRemote.Close()
	defer linkRemote.Close()

	e := testEngine(t)
	var up, down uint64
	go e.relay(vpnLocal, linkLocal, &up, &down)

	// Sized to straddle the relay buffer: one below, one above, so a payload
	// that needs several reads is exercised as well as one that does not.
	payload := bytes.Repeat([]byte("openvpn"), (relayBuf/7)*3)

	var wg sync.WaitGroup
	wg.Add(2)
	got := make([][]byte, 2)

	go func() { // client -> exit
		defer wg.Done()
		go func() { _, _ = vpnRemote.Write(payload) }()
		buf := make([]byte, len(payload))
		_ = linkRemote.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(linkRemote, buf); err != nil {
			t.Errorf("client->exit: %v", err)
		}
		got[0] = buf
	}()
	go func() { // exit -> client
		defer wg.Done()
		go func() { _, _ = linkRemote.Write(payload) }()
		buf := make([]byte, len(payload))
		_ = vpnRemote.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(vpnRemote, buf); err != nil {
			t.Errorf("exit->client: %v", err)
		}
		got[1] = buf
	}()
	wg.Wait()

	for i, b := range got {
		if !bytes.Equal(b, payload) {
			t.Fatalf("direction %d came back altered (%d of %d bytes)", i, len(b), len(payload))
		}
	}
}

// Both halves must end together. A relay that leaves one direction running
// after the other has finished holds a carrier connection open for a VPN
// connection that is already gone, and enough of those is a server that quietly
// stops accepting anything.
func TestRelayEndsBothDirectionsTogether(t *testing.T) {
	vpnLocal, vpnRemote := net.Pipe()
	linkLocal, linkRemote := net.Pipe()

	e := testEngine(t)
	done := make(chan struct{})
	var up, down uint64
	go func() { e.relay(vpnLocal, linkLocal, &up, &down); close(done) }()

	// The VPN client hangs up; the carrier side must be closed too.
	_ = vpnRemote.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay outlived the connection it was carrying")
	}
	_ = linkRemote.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := linkRemote.Read(make([]byte, 1)); err == nil {
		t.Fatal("the carrier side was left open after the VPN side closed")
	}
}

// The relay buffer is a latency decision, not a throughput one: bytes held here
// are bytes the inner TCP has sent and not seen acknowledged, so they inflate
// its RTT estimate and its window with it. It must stay well under the
// general-purpose engine's, and still exceed one full segment so it never caps
// throughput.
func TestRelayBufferIsSizedForLatency(t *testing.T) {
	if relayBuf > 32<<10 {
		t.Fatalf("relay buffer is %d bytes — large buffers inflate the inner connection's "+
			"round-trip estimate, which is what makes TCP-over-TCP collapse under load", relayBuf)
	}
	if relayBuf < 4<<10 {
		t.Fatalf("relay buffer is %d bytes, smaller than a few full segments — this would "+
			"cost throughput for no latency gain", relayBuf)
	}
}

// The warm pool is what removes the handshake from in front of a connecting
// client, so it must never be zero, and must stay bounded however the profile
// is configured.
func TestWarmPoolStaysWithinSaneBounds(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{0, 4}, {1, 4}, {4, 4}, {8, 8}, {1000, 32},
	} {
		if got := warmPool(tc.in); got != tc.want {
			t.Fatalf("warmPool(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// A client that arrives while the tunnel is down must be refused quickly, not
// left hanging: OpenVPN's own retry is faster and cleaner than any wait here,
// and a hung connection burns the client's whole connect timeout first.
func TestAClientIsRefusedQuicklyWhenNoCarrierIsReady(t *testing.T) {
	e := testEngine(t)
	e.parked = make(chan *crypto.SecureConn) // never populated: the tunnel is down

	start := time.Now()
	got := e.claimCarrier(context.Background())
	el := time.Since(start)

	if got != nil {
		t.Fatal("a carrier was produced from an empty pool")
	}
	if el > claimWait+2*time.Second {
		t.Fatalf("waited %v for a carrier that was never coming; OpenVPN would have "+
			"retried and succeeded in less", el)
	}
	if el < claimWait/2 {
		t.Fatalf("gave up after %v — too fast to cover a carrier that is a moment "+
			"from being parked, which would refuse clients during an ordinary reconnect", el)
	}
}
