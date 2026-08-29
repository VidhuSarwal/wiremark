package collector

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// encodeEvent is the test-side mirror of what the BPF program writes: field
// order and padding must match bpf/types.h's struct event exactly.
func encodeEvent(t *testing.T, ev Event) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, ev); err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	return buf.Bytes()
}

func TestDecodeEventRoundTrip(t *testing.T) {
	want := Event{
		PID:        1234,
		TID:        5678,
		Timestamp:  9999999999,
		FD:         7,
		Operation:  OpConnect,
		Ret:        0,
		RemoteAddr: 0x0100007f, // 127.0.0.1 in network byte order little-endian layout
		RemotePort: 8080,
		DataLen:    0,
	}

	got, err := decodeEvent(encodeEvent(t, want))
	if err != nil {
		t.Fatalf("decodeEvent: %v", err)
	}
	if got != want {
		t.Fatalf("decodeEvent round trip mismatch:\n got:  %+v\n want: %+v", got, want)
	}
}

func TestDecodeEventWithPayload(t *testing.T) {
	want := Event{
		PID:       42,
		FD:        3,
		Operation: OpWrite,
		DataLen:   5,
	}
	copy(want.Data[:], "hello")

	got, err := decodeEvent(encodeEvent(t, want))
	if err != nil {
		t.Fatalf("decodeEvent: %v", err)
	}
	if string(got.Payload()) != "hello" {
		t.Fatalf("Payload() = %q, want %q", got.Payload(), "hello")
	}
}

func TestDecodeEventTruncatedRecord(t *testing.T) {
	if _, err := decodeEvent([]byte{1, 2, 3}); err == nil {
		t.Fatal("decodeEvent on a truncated record: got nil error, want one")
	}
}

func TestEventStructSizeMatchesCStruct(t *testing.T) {
	// bpf/types.h's struct event is 296 bytes: 4 __u32/​__s32 pairs (16) +
	// 8-byte timestamp + 4 more 4-byte fields (16) + 2-byte port + 2-byte
	// pad + 4-byte data_len + 256-byte data = 296, 8-byte aligned.
	const wantSize = 296
	if got := len(encodeEvent(t, Event{})); got != wantSize {
		t.Fatalf("encoded Event size = %d bytes, want %d (must match bpf/types.h's struct event)", got, wantSize)
	}
}

func TestRemoteAddrString(t *testing.T) {
	// 127.0.0.1 stored little-endian as the kernel writes sin_addr.s_addr.
	ev := Event{RemoteAddr: 0x0100007f, RemotePort: 443}
	want := "127.0.0.1:443"
	if got := ev.RemoteAddrString(); got != want {
		t.Fatalf("RemoteAddrString() = %q, want %q", got, want)
	}
}

func TestPayloadRespectsDataLen(t *testing.T) {
	ev := Event{DataLen: 3}
	copy(ev.Data[:], "abcdef")
	if got := string(ev.Payload()); got != "abc" {
		t.Fatalf("Payload() = %q, want %q", got, "abc")
	}
}
