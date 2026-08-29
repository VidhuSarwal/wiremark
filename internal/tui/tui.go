// Package tui is the bubbletea live-view consumer of the collector's Event
// stream. It never reads from the ring buffer directly -- it only consumes
// the same Event channel the plain-text printer does, which is what makes it
// testable headlessly with synthetic events (see tui_test.go).
package tui

import (
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/vidhu/etracer/internal/collector"
)

// maxRows bounds memory for long-running traces; older rows scroll off.
const maxRows = 500

type eventMsg struct {
	ev collector.Event
	t  time.Time
}

type channelClosedMsg struct{}

type model struct {
	table  table.Model
	events <-chan collector.Event
	timeOf func(collector.Event) time.Time
	rows   []table.Row
	closed bool
}

func newModel(events <-chan collector.Event, timeOf func(collector.Event) time.Time) model {
	t := table.New(
		table.WithColumns([]table.Column{
			{Title: "Time", Width: 12},
			{Title: "PID", Width: 8},
			{Title: "Comm", Width: 12},
			{Title: "FD", Width: 5},
			{Title: "Op", Width: 8},
			{Title: "Detail", Width: 60},
		}),
		table.WithFocused(true),
		table.WithHeight(20),
	)
	styles := table.DefaultStyles()
	styles.Header = styles.Header.Bold(true)
	styles.Selected = styles.Selected.Foreground(lipgloss.Color("229")).Background(lipgloss.Color("57"))
	t.SetStyles(styles)

	return model{table: t, events: events, timeOf: timeOf}
}

func waitForEvent(events <-chan collector.Event, timeOf func(collector.Event) time.Time) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-events
		if !ok {
			return channelClosedMsg{}
		}
		return eventMsg{ev: ev, t: timeOf(ev)}
	}
}

func (m model) Init() tea.Cmd {
	return waitForEvent(m.events, m.timeOf)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.table.SetWidth(msg.Width)
		m.table.SetHeight(msg.Height - 4)
	case eventMsg:
		m.rows = append(m.rows, row(msg.ev, msg.t))
		if len(m.rows) > maxRows {
			m.rows = m.rows[len(m.rows)-maxRows:]
		}
		m.table.SetRows(m.rows)
		m.table.GotoBottom()
		return m, waitForEvent(m.events, m.timeOf)
	case channelClosedMsg:
		m.closed = true
		return m, nil
	}

	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m model) View() string {
	footer := "q: quit"
	if m.closed {
		footer = "trace ended -- " + footer
	}
	return m.table.View() + "\n" + lipgloss.NewStyle().Faint(true).Render(footer)
}

func row(ev collector.Event, t time.Time) table.Row {
	return table.Row{
		t.Format("15:04:05.000"),
		fmt.Sprintf("%d", ev.PID),
		collector.Comm(ev.PID),
		fmt.Sprintf("%d", ev.FD),
		opName(ev.Operation),
		detail(ev),
	}
}

func opName(op uint32) string {
	switch op {
	case collector.OpConnect:
		return "CONNECT"
	case collector.OpWrite:
		return "WRITE"
	case collector.OpRead:
		return "READ"
	case collector.OpClose:
		return "CLOSE"
	default:
		return fmt.Sprintf("OP(%d)", op)
	}
}

func detail(ev collector.Event) string {
	switch ev.Operation {
	case collector.OpConnect:
		return "-> " + ev.RemoteAddrString()
	case collector.OpWrite, collector.OpRead:
		return fmt.Sprintf("%d bytes: %q", ev.DataLen, ev.Payload())
	default:
		return ""
	}
}

// Run launches the interactive TUI, blocking until the user quits or the
// event channel closes.
func Run(events <-chan collector.Event, timeOf func(collector.Event) time.Time) error {
	p := tea.NewProgram(newModel(events, timeOf), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
