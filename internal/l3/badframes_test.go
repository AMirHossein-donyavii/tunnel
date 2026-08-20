package l3

import (
	"bytes"
	"testing"

	"github.com/emergency-tunnel/et/internal/crypto"
)

// "bad_frames=118, rx=0" was the state of a production tunnel for days, and the
// number could not be acted on, because one counter was three different events
// added together:
//
//   - a datagram from the peer, addressed to this link, that would not decrypt
//   - a frame that decrypted and then did not parse as a control message
//   - traffic on the socket that was never ours in the first place
//
// The first means the two ends handshook and cannot read each other, which is a
// version or key mismatch and needs both servers changed. The last is ordinary
// internet noise on a public address and means nothing at all. Adding them
// together produced a number that looked alarming when it was harmless and
// looked harmless when it was fatal.
//
// So they are counted apart, and this pins that they stay apart.
func TestTheThreeKindsOfBadFrameAreCountedApart(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	send, err := crypto.NewDatagramForTest("aes-256-gcm", key, key)
	if err != nil {
		t.Fatal(err)
	}
	// A peer keyed differently: everything it sends will authenticate as
	// garbage, which is exactly what a version or key mismatch looks like.
	otherKey := bytes.Repeat([]byte{9}, 32)
	stranger, err := crypto.NewDatagramForTest("aes-256-gcm", otherKey, otherKey)
	if err != nil {
		t.Fatal(err)
	}

	conn := newLossyConn(0, 1)
	defer conn.Close()
	r := &datagramLink{conn: conn, dg: send,
		rbuf: make([]byte, dgramMaxFrame+crypto.DatagramOverhead+64),
		pbuf: make([]byte, 0, dgramMaxFrame+64)}
	w := &datagramLink{conn: conn, dg: stranger}

	before := authFailed.Load()
	beforeStrangers := notOurs.Load()

	// Five frames from a peer that does not share our key. The conn hands reads
	// straight back from a queue, so everything is written before anything is
	// read rather than racing a goroutine against an empty queue.
	const n = 5
	payload := make([]byte, 64)
	for i := 0; i < n; i++ {
		if err := w.WriteFrame(payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	for {
		if _, err := r.ReadFrame(); err != nil {
			break
		}
	}

	if got := authFailed.Load() - before; got < n {
		t.Fatalf("auth_failed counted %d of %d undecryptable datagrams from the peer — "+
			"this is the one counter that names a cause, and it has to be exact", got, n)
	}
	// Nothing here was another tunnel's traffic, and saying it was would send
	// the next person looking at the wrong thing entirely.
	if got := notOurs.Load() - beforeStrangers; got != 0 {
		t.Fatalf("not_ours counted %d frames from our own configured peer — a decryption "+
			"failure is not background noise and must never be filed as it", got)
	}
}

// A replayed datagram is the second copy of a small frame that this tunnel sent
// deliberately, so it must not be recorded as an authentication failure. It
// used to be, and on an idle tunnel — where every frame is small and therefore
// duplicated — that walked the counter up until the link was torn down for a
// flood of "bad" datagrams that it had itself asked for.
func TestADuplicateIsNotAnAuthenticationFailure(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	send, err := crypto.NewDatagramForTest("aes-256-gcm", key, key)
	if err != nil {
		t.Fatal(err)
	}
	recv, err := crypto.NewDatagramForTest("aes-256-gcm", key, key)
	if err != nil {
		t.Fatal(err)
	}

	conn := newLossyConn(0, 1)
	defer conn.Close()
	w := &datagramLink{conn: conn, dg: send}
	r := &datagramLink{conn: conn, dg: recv,
		rbuf: make([]byte, dgramMaxFrame+crypto.DatagramOverhead+64),
		pbuf: make([]byte, 0, dgramMaxFrame+64)}

	before := authFailed.Load()
	// Small enough that WriteFrame sends it twice, which is the whole point.
	if err := w.WriteFrame(make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := r.ReadFrame(); err != nil {
			break
		}
	}
	if got := authFailed.Load() - before; got != 0 {
		t.Fatalf("a deliberate duplicate was counted as %d authentication failures — "+
			"the tunnel would be reporting its own retransmission as an attack", got)
	}
}
