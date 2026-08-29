package tui

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/charmbracelet/x/exp/teatest"

	"github.com/vidhu/etracer/internal/collector"
)

// fixedTime lets tests assert on exact rendered timestamps.
var fixedTime = time.Date(2026, 1, 1, 12, 31, 1, 142_000_000, time.UTC)

func newTestModel(t *testing.T) (*teatest.TestModel, chan collector.Event) {
	t.Helper()
	events := make(chan collector.Event)
	m := newModel(events, func(collector.Event) time.Time { return fixedTime })
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(120, 30))
	t.Cleanup(func() { close(events) })
	return tm, events
}

func TestTUIRendersEvent(t *testing.T) {
	tm, _ := newTestModel(t)

	tm.Send(eventMsg{
		ev: collector.Event{
			PID: 18231, FD: 7, Operation: collector.OpConnect,
			RemoteAddr: 0x0500000a, RemotePort: 5432,
		},
		t: fixedTime,
	})

	teatest.WaitFor(t, tm.Output(), func(out []byte) bool {
		return bytes.Contains(out, []byte("18231")) && bytes.Contains(out, []byte("CONNECT"))
	}, teatest.WithDuration(2*time.Second))

	tm.Type("q")
	tm.WaitFinished(t, teatest.WithFinalTimeout(2*time.Second))
}

func TestTUIShowsTraceEndedWhenChannelCloses(t *testing.T) {
	events := make(chan collector.Event)
	m := newModel(events, func(collector.Event) time.Time { return fixedTime })
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(120, 30))
	close(events)

	teatest.WaitFor(t, tm.Output(), func(out []byte) bool {
		return bytes.Contains(out, []byte("trace ended"))
	}, teatest.WithDuration(2*time.Second))

	tm.Type("q")
	tm.WaitFinished(t, teatest.WithFinalTimeout(2*time.Second))
}

func TestTUIRowCapBoundsMemory(t *testing.T) {
	const overflow = 50
	m := newModel(nil, func(collector.Event) time.Time { return fixedTime })

	for i := 0; i < maxRows+overflow; i++ {
		next, _ := m.Update(eventMsg{ev: collector.Event{PID: uint32(i), Operation: collector.OpClose}, t: fixedTime})
		m = next.(model)
	}

	if len(m.rows) != maxRows {
		t.Fatalf("row count = %d, want capped at %d", len(m.rows), maxRows)
	}
	wantFirst := fmt.Sprintf("%d", overflow)          // oldest `overflow` events scrolled off
	wantLast := fmt.Sprintf("%d", maxRows+overflow-1) // most recent event kept
	if got := m.rows[0][1]; got != wantFirst {
		t.Errorf("oldest kept row PID = %q, want %q", got, wantFirst)
	}
	if got := m.rows[len(m.rows)-1][1]; got != wantLast {
		t.Errorf("newest row PID = %q, want %q", got, wantLast)
	}
}
