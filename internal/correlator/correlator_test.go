package correlator

import (
	"testing"
	"time"

	"github.com/vidhusarwal/wiremark/internal/collector"
)

func fixedTimeOf(collector.Event) time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

func drainConns(t *testing.T, connOut <-chan Connection) []Connection {
	t.Helper()
	var got []Connection
	for c := range connOut {
		got = append(got, c)
	}
	return got
}

func runCorrelator(t *testing.T, events []collector.Event) []Connection {
	t.Helper()
	in := make(chan collector.Event, len(events))
	for _, ev := range events {
		in <- ev
	}
	close(in)

	rawOut, connOut := Run(in, fixedTimeOf)
	go func() {
		for range rawOut { // drain, unused by this test
		}
	}()
	return drainConns(t, connOut)
}

func TestConnectionTracksByteCounts(t *testing.T) {
	events := []collector.Event{
		{PID: 1, FD: 7, Operation: collector.OpConnect, RemoteAddr: 0x0100007f, RemotePort: 5432},
		{PID: 1, FD: 7, Operation: collector.OpWrite, TotalLen: 128, DataLen: 128},
		{PID: 1, FD: 7, Operation: collector.OpRead, TotalLen: 512, DataLen: 512},
		{PID: 1, FD: 7, Operation: collector.OpClose},
	}

	got := runCorrelator(t, events)
	if len(got) != 4 {
		t.Fatalf("got %d snapshots, want 4 (one per state change)", len(got))
	}

	final := got[len(got)-1]
	if !final.Closed {
		t.Error("final snapshot should be Closed")
	}
	if final.BytesOut != 128 {
		t.Errorf("BytesOut = %d, want 128", final.BytesOut)
	}
	if final.BytesIn != 512 {
		t.Errorf("BytesIn = %d, want 512", final.BytesIn)
	}
	if final.RemoteAddr != 0x0100007f || final.RemotePort != 5432 {
		t.Errorf("endpoint not preserved: addr=%#x port=%d", final.RemoteAddr, final.RemotePort)
	}
}

// TestFDReuseProducesDistinctConnections is the correctness case that
// matters most: the kernel reuses fd numbers, so a second connect() on the
// same (pid, fd) after a close() must start a fresh connection, not merge
// counts/endpoint into the previous one.
func TestFDReuseProducesDistinctConnections(t *testing.T) {
	events := []collector.Event{
		// First connection on fd 7: to 10.0.0.1, writes 100 bytes, closes.
		{PID: 1, FD: 7, Operation: collector.OpConnect, RemoteAddr: 0x0100000a, RemotePort: 111},
		{PID: 1, FD: 7, Operation: collector.OpWrite, TotalLen: 100, DataLen: 100},
		{PID: 1, FD: 7, Operation: collector.OpClose},
		// Second connection reuses fd 7: to 10.0.0.2, writes 200 bytes, closes.
		{PID: 1, FD: 7, Operation: collector.OpConnect, RemoteAddr: 0x0200000a, RemotePort: 222},
		{PID: 1, FD: 7, Operation: collector.OpWrite, TotalLen: 200, DataLen: 200},
		{PID: 1, FD: 7, Operation: collector.OpClose},
	}

	got := runCorrelator(t, events)

	var closedSnapshots []Connection
	for _, c := range got {
		if c.Closed {
			closedSnapshots = append(closedSnapshots, c)
		}
	}
	if len(closedSnapshots) != 2 {
		t.Fatalf("got %d closed snapshots, want 2 distinct connections", len(closedSnapshots))
	}

	first, second := closedSnapshots[0], closedSnapshots[1]
	if first.Seq == second.Seq {
		t.Error("both connections share a Seq -- they were merged")
	}
	if first.RemotePort != 111 || first.BytesOut != 100 {
		t.Errorf("first connection corrupted: port=%d bytesOut=%d", first.RemotePort, first.BytesOut)
	}
	if second.RemotePort != 222 || second.BytesOut != 200 {
		t.Errorf("second connection corrupted (likely merged with first): port=%d bytesOut=%d", second.RemotePort, second.BytesOut)
	}
}

// TestByteCountsUseTotalLenNotDataLen guards against the bug this fix
// corrected: a write/read larger than the capture buffer must still count
// its true byte total, not the truncated captured payload length.
func TestByteCountsUseTotalLenNotDataLen(t *testing.T) {
	events := []collector.Event{
		{PID: 1, FD: 7, Operation: collector.OpConnect},
		// A 10KB write, but only 4096 bytes of payload were captured.
		{PID: 1, FD: 7, Operation: collector.OpWrite, TotalLen: 10_000, DataLen: 4096},
	}

	got := runCorrelator(t, events)
	final := got[len(got)-1]
	if final.BytesOut != 10_000 {
		t.Fatalf("BytesOut = %d, want 10000 (the true count, not the 4096-byte capture cap)", final.BytesOut)
	}
}

func TestWriteOnUntrackedFDIsIgnored(t *testing.T) {
	// A write on an fd that never had a connect() (e.g. a file, or a socket
	// this trace missed the connect for) shouldn't fabricate a connection.
	events := []collector.Event{
		{PID: 1, FD: 3, Operation: collector.OpWrite, DataLen: 60},
		{PID: 1, FD: 3, Operation: collector.OpClose},
	}

	got := runCorrelator(t, events)
	if len(got) != 0 {
		t.Fatalf("got %d snapshots for an untracked fd, want 0", len(got))
	}
}

func TestRawPassthroughEmitsEveryEvent(t *testing.T) {
	events := []collector.Event{
		{PID: 1, FD: 7, Operation: collector.OpConnect},
		{PID: 1, FD: 7, Operation: collector.OpClose},
	}

	in := make(chan collector.Event, len(events))
	for _, ev := range events {
		in <- ev
	}
	close(in)

	rawOut, connOut := Run(in, fixedTimeOf)
	go drainConns(t, connOut)

	var n int
	for range rawOut {
		n++
	}
	if n != len(events) {
		t.Fatalf("rawOut passed through %d events, want %d", n, len(events))
	}
}
