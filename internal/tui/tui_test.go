package tui

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"

	"github.com/vidhu/etracer/internal/collector"
	"github.com/vidhu/etracer/internal/correlator"
)

// fixedTime lets tests assert on exact rendered timestamps.
var fixedTime = time.Date(2026, 1, 1, 12, 31, 1, 142_000_000, time.UTC)

func newTestModel(t *testing.T) (*teatest.TestModel, chan collector.Event, chan correlator.Connection) {
	t.Helper()
	events := make(chan collector.Event)
	conns := make(chan correlator.Connection)
	m := newModel(events, conns, func(collector.Event) time.Time { return fixedTime })
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(120, 30))
	t.Cleanup(func() {
		close(events)
		close(conns)
	})
	return tm, events, conns
}

// --- events tab: same behavior as the original M1 view, now under a tab ---

func TestTUIRendersEvent(t *testing.T) {
	tm, _, _ := newTestModel(t)

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
	conns := make(chan correlator.Connection)
	m := newModel(events, conns, func(collector.Event) time.Time { return fixedTime })
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(120, 30))
	close(events)
	close(conns)

	teatest.WaitFor(t, tm.Output(), func(out []byte) bool {
		return bytes.Contains(out, []byte("trace ended"))
	}, teatest.WithDuration(2*time.Second))

	tm.Type("q")
	tm.WaitFinished(t, teatest.WithFinalTimeout(2*time.Second))
}

func TestTUIRowCapBoundsMemory(t *testing.T) {
	const overflow = 50
	m := newModel(nil, nil, func(collector.Event) time.Time { return fixedTime })

	for i := 0; i < maxRows+overflow; i++ {
		next, _ := m.Update(eventMsg{ev: collector.Event{PID: uint32(i), Operation: collector.OpClose}, t: fixedTime})
		m = next.(Model)
	}

	if len(m.events.rows) != maxRows {
		t.Fatalf("row count = %d, want capped at %d", len(m.events.rows), maxRows)
	}
	wantFirst := fmt.Sprintf("%d", overflow)
	wantLast := fmt.Sprintf("%d", maxRows+overflow-1)
	if got := m.events.rows[0][1]; got != wantFirst {
		t.Errorf("oldest kept row PID = %q, want %q", got, wantFirst)
	}
	if got := m.events.rows[len(m.events.rows)-1][1]; got != wantLast {
		t.Errorf("newest row PID = %q, want %q", got, wantLast)
	}
}

// --- connections tab: M2 ---

func TestTUIConnectionsTabUpdatesRowInPlace(t *testing.T) {
	tm, _, conns := newTestModel(t)

	// Switch to the connections tab.
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})

	conns <- correlator.Connection{
		Seq: 1, PID: 42, FD: 7, Comm: "myapp",
		RemoteAddr: 0x0100007f, RemotePort: 5432,
	}
	teatest.WaitFor(t, tm.Output(), func(out []byte) bool {
		return bytes.Contains(out, []byte("myapp")) && bytes.Contains(out, []byte("127.0.0.1:5432"))
	}, teatest.WithDuration(2*time.Second))

	conns <- correlator.Connection{
		Seq: 1, PID: 42, FD: 7, Comm: "myapp",
		RemoteAddr: 0x0100007f, RemotePort: 5432, BytesOut: 128,
	}
	teatest.WaitFor(t, tm.Output(), func(out []byte) bool {
		return bytes.Contains(out, []byte("128"))
	}, teatest.WithDuration(2*time.Second))

	conns <- correlator.Connection{
		Seq: 1, PID: 42, FD: 7, Comm: "myapp",
		RemoteAddr: 0x0100007f, RemotePort: 5432, BytesOut: 128,
		Closed: true, ClosedAt: fixedTime,
	}
	teatest.WaitFor(t, tm.Output(), func(out []byte) bool {
		return bytes.Contains(out, []byte("closed"))
	}, teatest.WithDuration(2*time.Second))

	tm.Type("q")
	fm := tm.FinalModel(t, teatest.WithFinalTimeout(2*time.Second))
	final := fm.(Model)
	if len(final.conns.rows) != 1 {
		t.Fatalf("connections tab has %d rows, want 1 (updates should replace the row, not append)", len(final.conns.rows))
	}
}

func TestTUIConnectionsTabDistinctSeqAreDistinctRows(t *testing.T) {
	m := newModel(nil, nil, func(collector.Event) time.Time { return fixedTime })

	next, _ := m.Update(connMsg(correlator.Connection{Seq: 1, PID: 1, FD: 7, RemotePort: 111}))
	m = next.(Model)
	next, _ = m.Update(connMsg(correlator.Connection{Seq: 2, PID: 1, FD: 7, RemotePort: 222}))
	m = next.(Model)

	if len(m.conns.rows) != 2 {
		t.Fatalf("got %d rows for two distinct Seqs on the same (pid,fd), want 2", len(m.conns.rows))
	}
}
