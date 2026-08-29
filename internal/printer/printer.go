// Package printer is a plain-text consumer of the collector's Event stream,
// used for --no-tui mode and for testing decode/format logic without a
// terminal.
package printer

import (
	"fmt"
	"io"
	"time"

	"github.com/vidhu/etracer/internal/collector"
)

// Format renders a single event as one plain-text line. t is the event's
// wall-clock time and comm the resolved command name (or "?"), both supplied
// by the caller so this function stays a pure, easily-testable formatter.
func Format(ev collector.Event, comm string, t time.Time) string {
	prefix := fmt.Sprintf("[%s] PID %d (%s) fd=%d", t.Format("15:04:05.000"), ev.PID, comm, ev.FD)

	switch ev.Operation {
	case collector.OpConnect:
		return fmt.Sprintf("%s CONNECT -> %s", prefix, ev.RemoteAddrString())
	case collector.OpWrite:
		return fmt.Sprintf("%s WRITE %d bytes: %q", prefix, ev.DataLen, ev.Payload())
	case collector.OpRead:
		return fmt.Sprintf("%s READ %d bytes: %q", prefix, ev.DataLen, ev.Payload())
	case collector.OpClose:
		return fmt.Sprintf("%s CLOSE", prefix)
	default:
		return fmt.Sprintf("%s UNKNOWN(op=%d)", prefix, ev.Operation)
	}
}

// Print writes one formatted line per event to w until events closes.
func Print(w io.Writer, events <-chan collector.Event, timeOf func(collector.Event) time.Time) {
	for ev := range events {
		fmt.Fprintln(w, Format(ev, collector.Comm(ev.PID), timeOf(ev)))
	}
}
