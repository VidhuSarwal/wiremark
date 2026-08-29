// Package tui is the bubbletea live-view consumer of the collector's Event
// stream and the correlator's Connection stream. It never reads from the
// ring buffer or the collector directly -- it only consumes channels, which
// is what makes it testable headlessly with synthetic values (see
// tui_test.go).
package tui

import (
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/vidhu/etracer/internal/collector"
	"github.com/vidhu/etracer/internal/correlator"
	"github.com/vidhu/etracer/internal/streamer"
)

// maxRows bounds memory for long-running traces; older rows scroll off.
const maxRows = 500

func defaultTableStyles() table.Styles {
	s := table.DefaultStyles()
	s.Header = s.Header.Bold(true)
	s.Selected = s.Selected.Foreground(lipgloss.Color("229")).Background(lipgloss.Color("57"))
	return s
}

func faint(s string) string {
	return lipgloss.NewStyle().Faint(true).Render(s)
}

// ---- events tab: the flat M1 log, unchanged behavior ----

type eventMsg struct {
	ev collector.Event
	t  time.Time
}

type eventsClosedMsg struct{}

type eventsTab struct {
	table  table.Model
	events <-chan collector.Event
	timeOf func(collector.Event) time.Time
	rows   []table.Row
	closed bool
}

func newEventsTab(events <-chan collector.Event, timeOf func(collector.Event) time.Time) eventsTab {
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
	t.SetStyles(defaultTableStyles())
	return eventsTab{table: t, events: events, timeOf: timeOf}
}

func waitForEvent(events <-chan collector.Event, timeOf func(collector.Event) time.Time) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-events
		if !ok {
			return eventsClosedMsg{}
		}
		return eventMsg{ev: ev, t: timeOf(ev)}
	}
}

func (m eventsTab) init() tea.Cmd {
	return waitForEvent(m.events, m.timeOf)
}

func (m eventsTab) update(msg tea.Msg) (eventsTab, tea.Cmd) {
	switch msg := msg.(type) {
	case eventMsg:
		m.rows = append(m.rows, eventRow(msg.ev, msg.t))
		if len(m.rows) > maxRows {
			m.rows = m.rows[len(m.rows)-maxRows:]
		}
		m.table.SetRows(m.rows)
		m.table.GotoBottom()
		return m, waitForEvent(m.events, m.timeOf)
	case eventsClosedMsg:
		m.closed = true
		return m, nil
	}
	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m eventsTab) view(footer string) string {
	if m.closed {
		footer = "trace ended -- " + footer
	}
	return m.table.View() + "\n" + faint(footer)
}

func eventRow(ev collector.Event, t time.Time) table.Row {
	return table.Row{
		t.Format("15:04:05.000"),
		fmt.Sprintf("%d", ev.PID),
		collector.Comm(ev.PID),
		fmt.Sprintf("%d", ev.FD),
		opName(ev.Operation),
		eventDetail(ev),
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

func eventDetail(ev collector.Event) string {
	switch ev.Operation {
	case collector.OpConnect:
		return "-> " + ev.RemoteAddrString()
	case collector.OpWrite, collector.OpRead:
		return fmt.Sprintf("%d bytes: %q", ev.DataLen, ev.Payload())
	default:
		return ""
	}
}

// ---- connections tab: M2, grouped by (pid,fd) lifecycle ----

type connMsg correlator.Connection

type connsClosedMsg struct{}

type connsTab struct {
	table  table.Model
	conns  <-chan correlator.Connection
	index  map[uint64]int // Connection.Seq -> row index, for update-in-place
	rows   []table.Row
	closed bool
}

func newConnsTab(conns <-chan correlator.Connection) connsTab {
	t := table.New(
		table.WithColumns([]table.Column{
			{Title: "PID", Width: 8},
			{Title: "Comm", Width: 12},
			{Title: "FD", Width: 5},
			{Title: "Remote", Width: 22},
			{Title: "Out", Width: 10},
			{Title: "In", Width: 10},
			{Title: "State", Width: 8},
		}),
		table.WithFocused(true),
		table.WithHeight(20),
	)
	t.SetStyles(defaultTableStyles())
	return connsTab{table: t, conns: conns, index: make(map[uint64]int)}
}

func waitForConn(conns <-chan correlator.Connection) tea.Cmd {
	return func() tea.Msg {
		c, ok := <-conns
		if !ok {
			return connsClosedMsg{}
		}
		return connMsg(c)
	}
}

func (m connsTab) init() tea.Cmd {
	return waitForConn(m.conns)
}

func (m connsTab) update(msg tea.Msg) (connsTab, tea.Cmd) {
	switch msg := msg.(type) {
	case connMsg:
		c := correlator.Connection(msg)
		row := connRow(c)
		if idx, ok := m.index[c.Seq]; ok {
			m.rows[idx] = row
		} else {
			m.index[c.Seq] = len(m.rows)
			m.rows = append(m.rows, row)
		}
		m.table.SetRows(m.rows)
		return m, waitForConn(m.conns)
	case connsClosedMsg:
		m.closed = true
		return m, nil
	}
	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m connsTab) view(footer string) string {
	if m.closed {
		footer = "trace ended -- " + footer
	}
	return m.table.View() + "\n" + faint(footer)
}

func connRow(c correlator.Connection) table.Row {
	state := "open"
	if c.Closed {
		state = "closed"
	}
	return table.Row{
		fmt.Sprintf("%d", c.PID),
		c.Comm,
		fmt.Sprintf("%d", c.FD),
		c.RemoteAddrString(),
		fmt.Sprintf("%d", c.BytesOut),
		fmt.Sprintf("%d", c.BytesIn),
		state,
	}
}

// ---- HTTP tab: M3, one row per decoded exchange ----

type httpMsg streamer.Exchange

type httpClosedMsg struct{}

type httpTab struct {
	table     table.Model
	exchanges <-chan streamer.Exchange
	rows      []table.Row
	closed    bool
}

func newHTTPTab(exchanges <-chan streamer.Exchange) httpTab {
	t := table.New(
		table.WithColumns([]table.Column{
			{Title: "PID", Width: 8},
			{Title: "FD", Width: 5},
			{Title: "Method", Width: 8},
			{Title: "Path", Width: 20},
			{Title: "Status", Width: 8},
			{Title: "Body", Width: 40},
			{Title: "Trunc", Width: 6},
		}),
		table.WithFocused(true),
		table.WithHeight(20),
	)
	t.SetStyles(defaultTableStyles())
	return httpTab{table: t, exchanges: exchanges}
}

func waitForExchange(exchanges <-chan streamer.Exchange) tea.Cmd {
	return func() tea.Msg {
		ex, ok := <-exchanges
		if !ok {
			return httpClosedMsg{}
		}
		return httpMsg(ex)
	}
}

func (m httpTab) init() tea.Cmd {
	return waitForExchange(m.exchanges)
}

func (m httpTab) update(msg tea.Msg) (httpTab, tea.Cmd) {
	switch msg := msg.(type) {
	case httpMsg:
		ex := streamer.Exchange(msg)
		// This tab only shows HTTP exchanges -- Redis dependencies are
		// M4's `etrace record` output, not a TUI view (a live table isn't
		// the right shape for "the app's Redis calls during this trace").
		if ex.Protocol == streamer.ProtocolHTTP {
			m.rows = append(m.rows, httpRow(ex))
			if len(m.rows) > maxRows {
				m.rows = m.rows[len(m.rows)-maxRows:]
			}
			m.table.SetRows(m.rows)
			m.table.GotoBottom()
		}
		return m, waitForExchange(m.exchanges)
	case httpClosedMsg:
		m.closed = true
		return m, nil
	}
	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m httpTab) view(footer string) string {
	if m.closed {
		footer = "trace ended -- " + footer
	}
	return m.table.View() + "\n" + faint(footer)
}

func httpRow(ex streamer.Exchange) table.Row {
	method, path := "-", "-"
	var body []byte
	if ex.HTTP != nil && ex.HTTP.Request != nil {
		method = ex.HTTP.Request.Method
		path = ex.HTTP.Request.URL.Path
		body = ex.HTTP.RequestBody
	}
	status := "-"
	if ex.HTTP != nil && ex.HTTP.Response != nil {
		status = fmt.Sprintf("%d", ex.HTTP.Response.StatusCode)
		body = ex.HTTP.ResponseBody
	}
	preview := string(body)
	if len(preview) > 37 {
		preview = preview[:37] + "..."
	}
	trunc := ""
	if ex.Truncated {
		trunc = "yes"
	}
	return table.Row{
		fmt.Sprintf("%d", ex.PID),
		fmt.Sprintf("%d", ex.FD),
		method,
		path,
		status,
		preview,
		trunc,
	}
}

// ---- top-level model: tabs between the views above ----

type tab int

const (
	tabEvents tab = iota
	tabConnections
	tabHTTP
)

var tabNames = [...]string{tabEvents: "Events", tabConnections: "Connections", tabHTTP: "HTTP"}

type Model struct {
	active tab
	events eventsTab
	conns  connsTab
	http   httpTab
}

func newModel(rawEvents <-chan collector.Event, conns <-chan correlator.Connection, exchanges <-chan streamer.Exchange, timeOf func(collector.Event) time.Time) Model {
	return Model{
		events: newEventsTab(rawEvents, timeOf),
		conns:  newConnsTab(conns),
		http:   newHTTPTab(exchanges),
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.events.init(), m.conns.init(), m.http.init())
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "tab":
			m.active = (m.active + 1) % tab(len(tabNames))
			return m, nil
		}
	}
	if size, ok := msg.(tea.WindowSizeMsg); ok {
		h := size.Height - 4
		m.events.table.SetWidth(size.Width)
		m.events.table.SetHeight(h)
		m.conns.table.SetWidth(size.Width)
		m.conns.table.SetHeight(h)
		m.http.table.SetWidth(size.Width)
		m.http.table.SetHeight(h)
	}

	// Every tab must keep consuming its channel regardless of which is
	// visible, or an idle tab's channel backs up and blocks the goroutine
	// feeding it further upstream.
	var cmds [3]tea.Cmd
	m.events, cmds[0] = m.events.update(msg)
	m.conns, cmds[1] = m.conns.update(msg)
	m.http, cmds[2] = m.http.update(msg)
	return m, tea.Batch(cmds[0], cmds[1], cmds[2])
}

func (m Model) View() string {
	const footer = "tab: switch view  q: quit"

	var header string
	for i, name := range tabNames {
		if i > 0 {
			header += " "
		}
		if tab(i) == m.active {
			name = lipgloss.NewStyle().Underline(true).Render(name)
		}
		header += "[" + name + "]"
	}

	var body string
	switch m.active {
	case tabConnections:
		body = m.conns.view(footer)
	case tabHTTP:
		body = m.http.view(footer)
	default:
		body = m.events.view(footer)
	}
	return header + "\n" + body
}

// Run launches the interactive TUI, blocking until the user quits or all
// channels close.
func Run(rawEvents <-chan collector.Event, conns <-chan correlator.Connection, exchanges <-chan streamer.Exchange, timeOf func(collector.Event) time.Time) error {
	p := tea.NewProgram(newModel(rawEvents, conns, exchanges, timeOf), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
