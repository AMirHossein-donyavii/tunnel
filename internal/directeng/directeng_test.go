package directeng

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/emergency-tunnel/et/internal/crypto"
)

// securePair returns two ends of an encrypted link, as the engine sees them.
func securePair(t *testing.T) (*crypto.SecureConn, *crypto.SecureConn) {
	t.Helper()
	c1, c2 := net.Pipe()
	type res struct {
		sc  *crypto.SecureConn
		err error
	}
	ch := make(chan res, 1)
	go func() { sc, err := crypto.ClientHandshake(c1, "chacha20-poly1305"); ch <- res{sc, err} }()
	srv, err := crypto.ServerHandshake(c2, "chacha20-poly1305")
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() { r.sc.Close(); srv.Close() })
	return r.sc, srv
}

func TestDestHeaderRoundTrip(t *testing.T) {
	cli, srv := securePair(t)
	dest := make([]byte, 2)
	binary.BigEndian.PutUint16(dest, 8443)
	dest = append(dest, []byte("PROXYv2-ish-header")...)

	go func() { _ = writeDest(cli, dest) }()
	got, err := readDest(srv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dest) {
		t.Fatalf("destination header did not survive: %q vs %q", got, dest)
	}
	if p := binary.BigEndian.Uint16(got[:2]); p != 8443 {
		t.Errorf("port decoded as %d", p)
	}
}

// A hostile or broken peer must not be able to make the exit allocate an
// arbitrary buffer or block forever.
func TestDestHeaderRejectsBadLength(t *testing.T) {
	for _, n := range []uint16{0, 1, maxDest + 1, 65535} {
		cli, srv := securePair(t)
		var h [2]byte
		binary.BigEndian.PutUint16(h[:], n)
		go func() { _, _ = cli.Write(h[:]) }()
		if _, err := readDest(srv); err == nil {
			t.Errorf("length %d was accepted", n)
		}
	}
}

func TestWriteDestRejectsOversize(t *testing.T) {
	cli, _ := securePair(t)
	if err := writeDest(cli, make([]byte, maxDest+1)); err == nil {
		t.Fatal("an oversized destination header was accepted")
	}
}

func TestReadDestOnClosedLink(t *testing.T) {
	cli, srv := securePair(t)
	cli.Close()
	if _, err := readDest(srv); err == nil || err == io.EOF && false {
		if err == nil {
			t.Fatal("readDest succeeded on a closed link")
		}
	}
}
