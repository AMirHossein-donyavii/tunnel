package l3

import (
	"bufio"
	"bytes"
	"testing"
)

func TestDatagramRoundTrip(t *testing.T) {
	pkts := [][]byte{
		[]byte("hello"),
		bytes.Repeat([]byte{0xAB}, 1380),
		{},          // zero-length payload is a heartbeat when written via appendHeartbeat
		[]byte("z"), // single byte
	}

	// Encode a batch: two packets, a heartbeat, then a packet.
	var buf []byte
	buf = appendPacket(buf, pkts[0])
	buf = appendPacket(buf, pkts[1])
	buf = appendHeartbeat(buf)
	buf = appendPacket(buf, pkts[3])

	r := bufio.NewReader(bytes.NewReader(buf))
	read := make([]byte, maxPacket)

	// packet 0
	n, hb, err := readDatagram(r, read)
	if err != nil || hb || string(read[:n]) != "hello" {
		t.Fatalf("pkt0: n=%d hb=%v err=%v", n, hb, err)
	}
	// packet 1
	n, hb, err = readDatagram(r, read)
	if err != nil || hb || n != 1380 || !bytes.Equal(read[:n], pkts[1]) {
		t.Fatalf("pkt1: n=%d hb=%v err=%v", n, hb, err)
	}
	// heartbeat
	n, hb, err = readDatagram(r, read)
	if err != nil || !hb || n != 0 {
		t.Fatalf("heartbeat: n=%d hb=%v err=%v", n, hb, err)
	}
	// packet 3
	n, hb, err = readDatagram(r, read)
	if err != nil || hb || string(read[:n]) != "z" {
		t.Fatalf("pkt3: n=%d hb=%v err=%v", n, hb, err)
	}
}

func TestReadDatagramTruncatedBuffer(t *testing.T) {
	var buf []byte
	buf = appendPacket(buf, bytes.Repeat([]byte{1}, 100))
	r := bufio.NewReader(bytes.NewReader(buf))
	small := make([]byte, 10) // too small
	if _, _, err := readDatagram(r, small); err == nil {
		t.Fatal("expected error for oversized datagram vs small buffer")
	}
}
