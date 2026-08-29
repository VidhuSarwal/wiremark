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
	// bpf/types.h's struct event: pid+tid (8) + timestamp (8) + fd+op+ret
	// (12), padded 4 bytes to align ssl_ptr (8) on an 8-byte boundary (28
	// -> 32) + remote_addr (4) + remote_port (2) + 2-byte pad + total_len
	// (4) + data_len (4) + data[4096] = 4152, already an 8-byte multiple
	// (no trailing padding needed) -- checked against a real C compilation
	// of the struct via offsetof() while adding ssl_ptr for TLS uprobes.
	const wantSize = 4152
	if got := len(encodeEvent(t, Event{})); got != wantSize {
		t.Fatalf("encoded Event size = %d bytes, want %d (must match bpf/types.h's struct event)", got, wantSize)
	}
}

func TestDecodeEventSSLReadRoundTrip(t *testing.T) {
	want := Event{
		PID:       42,
		FD:        -1, // no fd is recoverable in-kernel from an SSL* alone
		Operation: OpSSLRead,
		SSLPtr:    0xdeadbeefcafe,
		TotalLen:  5,
		DataLen:   5,
	}
	copy(want.Data[:], "hello")

	got, err := decodeEvent(encodeEvent(t, want))
	if err != nil {
		t.Fatalf("decodeEvent: %v", err)
	}
	if got.SSLPtr != want.SSLPtr || got.FD != -1 || string(got.Payload()) != "hello" {
		t.Fatalf("decodeEvent round trip mismatch:\n got:  %+v\n want: %+v", got, want)
	}
}

func TestTruncated(t *testing.T) {
	tests := []struct {
		name              string
		totalLen, dataLen uint32
		want              bool
	}{
		{"fully captured", 100, 100, false},
		{"truncated", 5000, 4096, true},
		{"zero-length event", 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := Event{TotalLen: tt.totalLen, DataLen: tt.dataLen}
			if got := ev.Truncated(); got != tt.want {
				t.Errorf("Truncated() = %v, want %v", got, tt.want)
			}
		})
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
