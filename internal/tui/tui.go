// Package tui is the bubbletea live-view consumer of the collector's Event
// stream and the correlator's Connection stream. It never reads from the
// ring buffer or the collector directly -- it only consumes channels, which
// is what makes it testable headlessly with synthetic values (see
// tui_test.go).
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/vidhusarwal/wiremark/internal/collector"
	"github.com/vidhusarwal/wiremark/internal/correlator"
	"github.com/vidhusarwal/wiremark/internal/streamer"
)

// maxRows bounds memory for long-running traces; older rows scroll off.
const maxRows = 500

// ---- chrome palette ----
//
// Coloring happens by post-processing each already-rendered, already-padded
// table line and re-styling one column's text in place -- never by putting
// ANSI codes into a table.Row value before it reaches bubbles/table. That
// table renders with mattn/go-runewidth, which is not ANSI-aware: it counts
// escape bytes as visible width and truncates styled cell content into
// broken escape sequences. Coloring after the library's own truncation and
// padding sidesteps that entirely.
var (
	colorAccent = lipgloss.Color("141")
	colorBarBg  = lipgloss.Color("236")
	colorLive   = lipgloss.Color("84")
	colorEnded  = lipgloss.Color("203")

	colorCyan    = lipgloss.Color("51")
	colorGreen   = lipgloss.Color("84")
	colorYellow  = lipgloss.Color("228")
	colorRed     = lipgloss.Color("203")
	colorMagenta = lipgloss.Color("213")
	colorDim     = lipgloss.Color("244")
	colorBlue    = lipgloss.Color("111")
)

func defaultTableStyles() table.Styles {
	s := table.DefaultStyles()
	s.Header = s.Header.Bold(true).Foreground(colorAccent)
	s.Selected = s.Selected.Foreground(lipgloss.Color("229")).Background(lipgloss.Color("57"))
	return s
}

// columnStart returns the offset (in runes) of column idx's content within a
// rendered table line, and its content width. It mirrors bubbles/table's own
// layout math exactly: DefaultStyles' Cell/Header styles carry Padding(0, 1),
// so each column occupies col.Width+2 runes, with content starting 1 rune
// in from the column's left edge.
func columnStart(cols []table.Column, idx int) (offset, width int) {
	pos := 0
	for i, c := range cols {
		if i == idx {
			return pos + 1, c.Width
		}
		pos += c.Width + 2
	}
	return -1, 0
}

// colorizeAt re-renders the content in line[offset:offset+width] (trimming
// trailing pad spaces first, so the injected escape codes never touch the
// padding bubbles/table already computed) in the given color, leaving every
// other rune -- including that padding -- untouched.
func colorizeAt(line string, offset, width int, color lipgloss.Color) string {
	runes := []rune(line)
	if offset < 0 || width <= 0 || offset+width > len(runes) {
		return line
	}
	cell := string(runes[offset : offset+width])
	trimmed := strings.TrimRight(cell, " ")
	if trimmed == "" {
		return line
	}
	pad := cell[len(trimmed):]
	styled := lipgloss.NewStyle().Foreground(color).Render(trimmed)
	return string(runes[:offset]) + styled + pad + string(runes[offset+width:])
}

// colorizeColumn applies colorFn (given the trimmed cell text) to column
// colIdx of every data row in a rendered table.View() string, skipping the
// header line.
func colorizeColumn(view string, cols []table.Column, colIdx int, colorFn func(string) lipgloss.Color) string {
	offset, width := columnStart(cols, colIdx)
	if offset < 0 {
		return view
	}
	lines := strings.Split(view, "\n")
	for i := 1; i < len(lines); i++ {
		runes := []rune(lines[i])
		if offset+width > len(runes) {
			continue
		}
		token := strings.TrimSpace(string(runes[offset : offset+width]))
		if token == "" {
			continue
		}
		lines[i] = colorizeAt(lines[i], offset, width, colorFn(token))
	}
	return strings.Join(lines, "\n")
}

func opColor(op string) lipgloss.Color {
	switch {
	case strings.HasPrefix(op, "CONNECT"):
		return colorCyan
	case strings.HasPrefix(op, "READ"):
		return colorGreen
	case strings.HasPrefix(op, "WRITE"):
		return colorYellow
	case strings.HasPrefix(op, "CLOSE"):
		return colorDim
	case strings.HasPrefix(op, "SSL_"):
		return colorMagenta
	default:
		return colorDim
	}
}

func methodColor(method string) lipgloss.Color {
	switch method {
	case "GET":
		return colorBlue
	case "POST", "PUT", "PATCH":
		return colorGreen
	case "DELETE":
		return colorRed
	default:
		return colorDim
	}
}

func statusColor(status string) lipgloss.Color {
	if status == "" || status == "-" {
		return colorDim
	}
	switch status[0] {
	case '2':
		return colorGreen
	case '3':
		return colorBlue
	case '4':
		return colorYellow
	case '5':
		return colorRed
	default:
		return colorDim
	}
}

func stateColor(state string) lipgloss.Color {
	if state == "open" {
		return colorGreen
	}
	return colorDim
}

func truncColor(v string) lipgloss.Color {
	if v == "yes" {
		return colorYellow
	}
	return colorDim
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

func (m eventsTab) view() string {
	return colorizeColumn(m.table.View(), m.table.Columns(), 4, opColor)
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
	case collector.OpSSLWrite:
		return "SSL_WRITE"
	case collector.OpSSLRead:
		return "SSL_READ"
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
	case collector.OpSSLWrite, collector.OpSSLRead:
		return fmt.Sprintf("ssl=%#x %d bytes: %q", ev.SSLPtr, ev.DataLen, ev.Payload())
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

func (m connsTab) view() string {
	return colorizeColumn(m.table.View(), m.table.Columns(), 6, stateColor)
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

func (m httpTab) view() string {
	v := m.table.View()
	v = colorizeColumn(v, m.table.Columns(), 2, methodColor)
	v = colorizeColumn(v, m.table.Columns(), 4, statusColor)
	v = colorizeColumn(v, m.table.Columns(), 6, truncColor)
	return v
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

// ---- top-level model: tabs between the views above, plus chrome ----

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
	width  int
	height int
}

func newModel(rawEvents <-chan collector.Event, conns <-chan correlator.Connection, exchanges <-chan streamer.Exchange, timeOf func(collector.Event) time.Time) Model {
	return Model{
		events: newEventsTab(rawEvents, timeOf),
		conns:  newConnsTab(conns),
		http:   newHTTPTab(exchanges),
		width:  80,
		height: 24,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.events.init(), m.conns.init(), m.http.init())
}

// chromeHeight is how many lines the border, title bar, tab bar, and footer
// bar consume beyond the active tab's table (which renders its own header
// line as part of table.View()).
const chromeHeight = 2 /* border */ + 1 /* title */ + 1 /* tabs */ + 1 /* footer */
const chromeWidth = 4 /* border + inner padding, both sides */

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
		m.width, m.height = size.Width, size.Height
		w := size.Width - chromeWidth
		h := size.Height - chromeHeight
		if w < 1 {
			w = 1
		}
		if h < 1 {
			h = 1
		}
		m.events.table.SetWidth(w)
		m.events.table.SetHeight(h)
		m.conns.table.SetWidth(w)
		m.conns.table.SetHeight(h)
		m.http.table.SetWidth(w)
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

// barWidth is the interior width available to the title/tab/footer bars,
// i.e. the terminal width minus the outer border and its padding.
func (m Model) barWidth() int {
	w := m.width - chromeWidth
	if w < 1 {
		w = 1
	}
	return w
}

func titleBar(width int, live bool) string {
	status, statusFg := "● LIVE", colorLive
	if !live {
		status, statusFg = "● trace ended", colorEnded
	}
	leftStyle := lipgloss.NewStyle().Background(colorBarBg).Foreground(lipgloss.Color("255")).Bold(true)
	rightStyle := lipgloss.NewStyle().Background(colorBarBg).Foreground(statusFg).Bold(true)
	fillStyle := lipgloss.NewStyle().Background(colorBarBg)

	left := leftStyle.Render(" Wiremark ")
	right := rightStyle.Render(status + " ")
	gap := width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 0 {
		gap = 0
	}
	return left + fillStyle.Render(strings.Repeat(" ", gap)) + right
}

func tabBar(width int, active tab) string {
	activeStyle := lipgloss.NewStyle().Background(colorAccent).Foreground(lipgloss.Color("235")).Bold(true).Padding(0, 2)
	inactiveStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Padding(0, 2)

	var parts []string
	for i, name := range tabNames {
		if tab(i) == active {
			parts = append(parts, activeStyle.Render(name))
		} else {
			parts = append(parts, inactiveStyle.Render(name))
		}
	}
	return lipgloss.NewStyle().Width(width).Render(strings.Join(parts, " "))
}

func footerBar(width int) string {
	keyStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("235")).Background(colorAccent).Padding(0, 1)
	descStyle := lipgloss.NewStyle().Foreground(colorDim)
	line := keyStyle.Render("TAB") + descStyle.Render(" switch view    ") +
		keyStyle.Render("Q") + descStyle.Render(" quit")
	return lipgloss.NewStyle().Width(width).Render(line)
}

func (m Model) View() string {
	width := m.barWidth()

	var body string
	var live bool
	switch m.active {
	case tabConnections:
		body, live = m.conns.view(), !m.conns.closed
	case tabHTTP:
		body, live = m.http.view(), !m.http.closed
	default:
		body, live = m.events.view(), !m.events.closed
	}

	inner := strings.Join([]string{
		titleBar(width, live),
		tabBar(width, m.active),
		body,
		footerBar(width),
	}, "\n")

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorAccent).
		Padding(0, 1).
		Render(inner)
}

// Run launches the interactive TUI, blocking until the user quits or all
// channels close.
func Run(rawEvents <-chan collector.Event, conns <-chan correlator.Connection, exchanges <-chan streamer.Exchange, timeOf func(collector.Event) time.Time) error {
	p := tea.NewProgram(newModel(rawEvents, conns, exchanges, timeOf), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
