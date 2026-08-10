package l3

import (
	"bytes"
	"testing"
)

// splitFrame decodes a frame the way linkToTun does, so the test exercises the
// same length-discrimination rules.
func splitFrame(frame []byte) (packets [][]byte, ctls []ctlMsg, heartbeats int) {
	for len(frame) >= 2 {
		plen := int(frame[0])<<8 | int(frame[1])
		frame = frame[2:]
		if plen == 0 {
			heartbeats++
			continue
		}
		if plen > len(frame) {
			break
		}
		payload := frame[:plen]
		frame = frame[plen:]
		if plen < minIPPacket {
			if op, ts, ok := parseControl(payload); ok {
				ctls = append(ctls, ctlMsg{op: op, ts: ts})
			}
			continue
		}
		packets = append(packets, append([]byte(nil), payload...))
	}
	return packets, ctls, heartbeats
}

func TestFrameRoundTrip(t *testing.T) {
	big := bytes.Repeat([]byte{0xAB}, 1380)
	small := append([]byte{0x45}, bytes.Repeat([]byte{1}, minIPPacket-1)...) // exactly 20 bytes

	var buf []byte
	buf = appendPacket(buf, big)
	buf = appendControl(buf, ctlPing, 0x1122334455667788)
	buf = appendPacket(buf, small)
	buf = appendControl(buf, ctlPong, 42)

	packets, ctls, hb := splitFrame(buf)
	if hb != 0 {
		t.Errorf("unexpected heartbeats: %d", hb)
	}
	if len(packets) != 2 {
		t.Fatalf("got %d packets, want 2", len(packets))
	}
	if !bytes.Equal(packets[0], big) || !bytes.Equal(packets[1], small) {
		t.Error("packet payloads did not survive the round trip")
	}
	if len(ctls) != 2 {
		t.Fatalf("got %d control messages, want 2", len(ctls))
	}
	if ctls[0].op != ctlPing || ctls[0].ts != 0x1122334455667788 {
		t.Errorf("ping decoded as %+v", ctls[0])
	}
	if ctls[1].op != ctlPong || ctls[1].ts != 42 {
		t.Errorf("pong decoded as %+v", ctls[1])
	}
}

// A peer running an older core sends a bare zero-length heartbeat. It must stay
// decodable (and must not be mistaken for a packet) so liveness still works.
func TestLegacyHeartbeatIsTolerated(t *testing.T) {
	buf := append([]byte{0, 0}, appendPacket(nil, bytes.Repeat([]byte{9}, 40))...)
	packets, ctls, hb := splitFrame(buf)
	if hb != 1 || len(packets) != 1 || len(ctls) != 0 {
		t.Fatalf("hb=%d packets=%d ctls=%d", hb, len(packets), len(ctls))
	}
}

func TestParseControlRejectsGarbage(t *testing.T) {
	cases := [][]byte{
		{},                             // empty
		{ctlPing},                      // no timestamp
		{0x7f, 1, 2, 3, 4, 5, 6, 7, 8}, // unknown opcode
		{ctlPing, 1, 2, 3, 4, 5, 6, 7}, // one byte short
	}
	for i, c := range cases {
		if _, _, ok := parseControl(c); ok {
			t.Errorf("case %d: parseControl accepted %v", i, c)
		}
	}
}

// A truncated frame must be dropped, not read past its end.
func TestTruncatedFrameStops(t *testing.T) {
	buf := appendPacket(nil, bytes.Repeat([]byte{7}, 100))
	packets, _, _ := splitFrame(buf[:len(buf)-10])
	if len(packets) != 0 {
		t.Fatalf("truncated frame yielded %d packets", len(packets))
	}
}
