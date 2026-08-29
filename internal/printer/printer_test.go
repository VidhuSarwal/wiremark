package printer

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/vidhu/etracer/internal/collector"
)

func TestFormat(t *testing.T) {
	fixedTime := time.Date(2026, 1, 1, 12, 31, 1, 142_000_000, time.UTC)

	tests := []struct {
		name string
		ev   collector.Event
		want string
	}{
		{
			name: "connect",
			ev: collector.Event{
				PID: 18231, FD: 7, Operation: collector.OpConnect,
				RemoteAddr: 0x0500000a, RemotePort: 5432,
			},
			want: "[12:31:01.142] PID 18231 (myapp) fd=7 CONNECT -> 10.0.0.5:5432",
		},
		{
			name: "write",
			ev: collector.Event{
				PID: 18231, FD: 7, Operation: collector.OpWrite, DataLen: 5,
			},
			want: `[12:31:01.142] PID 18231 (myapp) fd=7 WRITE 5 bytes: "hello"`,
		},
		{
			name: "read",
			ev: collector.Event{
				PID: 18231, FD: 7, Operation: collector.OpRead, DataLen: 5,
			},
			want: `[12:31:01.142] PID 18231 (myapp) fd=7 READ 5 bytes: "hello"`,
		},
		{
			name: "close",
			ev:   collector.Event{PID: 18231, FD: 7, Operation: collector.OpClose},
			want: "[12:31:01.142] PID 18231 (myapp) fd=7 CLOSE",
		},
		{
			name: "unknown operation",
			ev:   collector.Event{PID: 1, FD: 0, Operation: 99},
			want: "[12:31:01.142] PID 1 (myapp) fd=0 UNKNOWN(op=99)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copy(tt.ev.Data[:], "hello")
			got := Format(tt.ev, "myapp", fixedTime)
			if got != tt.want {
				t.Errorf("Format() =\n  %q\nwant\n  %q", got, tt.want)
			}
		})
	}
}

func TestPrintWritesOneLinePerEvent(t *testing.T) {
	events := make(chan collector.Event, 2)
	events <- collector.Event{PID: 1, Operation: collector.OpClose}
	events <- collector.Event{PID: 2, Operation: collector.OpClose}
	close(events)

	var buf bytes.Buffer
	Print(&buf, events, func(collector.Event) time.Time { return time.Unix(0, 0) })

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("Print() wrote %d lines, want 2:\n%s", len(lines), buf.String())
	}
}
