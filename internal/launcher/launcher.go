package launcher

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// Mode is one of the top-level actions the launcher can assemble a command
// for.
type Mode int

const (
	ModeTraceTUI Mode = iota
	ModeTraceNoTUI
	ModeTraceTLS
	ModeRecord
	ModeRun
)

// Result is the assembled command the launcher hands back to cmd/wiremark to
// exec once the interactive flow completes. Args are the arguments to
// etrace itself (not including argv[0]).
type Result struct {
	Args      []string
	NeedsSudo bool
}

// modeItem adapts a Mode to list.DefaultItem for the mode-selection list.
type modeItem struct {
	mode        Mode
	title, desc string
}

func (i modeItem) Title() string       { return i.title }
func (i modeItem) Description() string { return i.desc }
func (i modeItem) FilterValue() string { return i.title }

// procItem adapts a Process to list.DefaultItem for the PID-selection list.
type procItem struct{ p Process }

func (i procItem) Title() string       { return fmt.Sprintf("%d  %s", i.p.PID, i.p.Comm) }
func (i procItem) Description() string { return "" }
func (i procItem) FilterValue() string { return fmt.Sprintf("%d %s", i.p.PID, i.p.Comm) }

// stage tracks where in the mode-first flow the model currently is. The
// modes don't share an input shape -- trace/trace-tls need only a PID,
// record needs a PID plus an output path, run needs a YAML path plus a
// command to exec -- so each mode branches to its own sequence of stages
// rather than forcing everything through one generic "pick a target" step.
type stage int

const (
	stageMode stage = iota
	stageTarget
	stageOutput
	stageYAML
	stageCommand
	stageDone
	stageQuit
)

type model struct {
	stage stage

	modeList list.Model
	procList list.Model
	textIn   textinput.Model

	mode     Mode
	pid      uint32
	yamlPath string
	result   Result
}

func newModel(processes []Process, yamlDefault string) model {
	modeItems := []list.Item{
		modeItem{ModeTraceTUI, "Trace (interactive TUI)", "Live syscall trace with the terminal UI"},
		modeItem{ModeTraceNoTUI, "Trace (plain text)", "Live syscall trace, printed as plain text"},
		modeItem{ModeTraceTLS, "Trace with TLS", "Trace plus decrypted SSL_write/SSL_read plaintext"},
		modeItem{ModeRecord, "Record a test case", "Capture one HTTP request + Redis deps as YAML"},
		modeItem{ModeRun, "Replay a test case (run)", "Serve a recorded test case's Redis deps to a command"},
	}
	modeList := list.New(modeItems, list.NewDefaultDelegate(), 0, 0)
	modeList.Title = "eTraceReplay — choose a mode"
	modeList.SetShowStatusBar(false)
	modeList.SetFilteringEnabled(false)

	procItems := make([]list.Item, len(processes))
	for i, p := range processes {
		procItems[i] = procItem{p}
	}
	procList := list.New(procItems, list.NewDefaultDelegate(), 0, 0)
	procList.Title = "choose a target process (type to filter)"

	ti := textinput.New()
	ti.CharLimit = 512

	return model{
		stage:    stageMode,
		modeList: modeList,
		procList: procList,
		textIn:   ti,
		yamlPath: yamlDefault,
	}
}

func (m model) Init() tea.Cmd { return nil }

func traceArgs(mode Mode, pid uint32) []string {
	args := []string{"trace", "--pid", strconv.Itoa(int(pid))}
	switch mode {
	case ModeTraceNoTUI:
		args = append(args, "--no-tui")
	case ModeTraceTLS:
		args = append(args, "--tls")
	}
	return args
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		h := msg.Height - 2
		m.modeList.SetSize(msg.Width, h)
		m.procList.SetSize(msg.Width, h)
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			m.stage = stageQuit
			return m, tea.Quit
		case "esc":
			// Esc while actively typing a list filter should cancel the
			// filter, not quit the whole launcher -- only treat it as
			// "quit" when nothing is capturing it for that purpose.
			if m.stage == stageTarget && m.procList.FilterState() == list.Filtering {
				break // fall through to the generic forward below
			}
			m.stage = stageQuit
			return m, tea.Quit

		case "enter":
			switch m.stage {
			case stageMode:
				item, ok := m.modeList.SelectedItem().(modeItem)
				if !ok {
					return m, nil
				}
				m.mode = item.mode
				switch m.mode {
				case ModeTraceTUI, ModeTraceNoTUI, ModeTraceTLS, ModeRecord:
					m.stage = stageTarget
				case ModeRun:
					m.textIn.SetValue(m.yamlPath)
					m.textIn.Placeholder = "test.yaml"
					m.textIn.CursorEnd()
					m.textIn.Focus()
					m.stage = stageYAML
				}
				return m, nil

			case stageTarget:
				// While the user is still typing a filter query, Enter
				// applies the filter (list's own job, via the forward
				// below) rather than confirming a selection.
				if m.procList.FilterState() == list.Filtering {
					break
				}
				item, ok := m.procList.SelectedItem().(procItem)
				if !ok {
					return m, nil
				}
				m.pid = item.p.PID
				if m.mode == ModeRecord {
					m.textIn.SetValue(fmt.Sprintf("recorded-%d.yaml", time.Now().Unix()))
					m.textIn.Placeholder = "output path"
					m.textIn.CursorEnd()
					m.textIn.Focus()
					m.stage = stageOutput
					return m, nil
				}
				m.result = Result{Args: traceArgs(m.mode, m.pid), NeedsSudo: true}
				m.stage = stageDone
				return m, tea.Quit

			case stageOutput:
				out := strings.TrimSpace(m.textIn.Value())
				if out == "" {
					return m, nil
				}
				m.result = Result{
					Args:      []string{"record", "--pid", strconv.Itoa(int(m.pid)), "-o", out},
					NeedsSudo: true,
				}
				m.stage = stageDone
				return m, tea.Quit

			case stageYAML:
				path := strings.TrimSpace(m.textIn.Value())
				if path == "" {
					return m, nil
				}
				m.yamlPath = path
				m.textIn.SetValue("")
				m.textIn.Placeholder = "command to run, e.g. ./your-app"
				m.stage = stageCommand
				return m, nil

			case stageCommand:
				cmdLine := strings.TrimSpace(m.textIn.Value())
				if cmdLine == "" {
					return m, nil
				}
				args := append([]string{"run", "--test", m.yamlPath, "--"}, strings.Fields(cmdLine)...)
				m.result = Result{Args: args, NeedsSudo: false}
				m.stage = stageDone
				return m, tea.Quit
			}
		}
	}

	// Everything not handled above -- list navigation keys, filter-query
	// runes, and message types this model has no opinion on at all (list's
	// async filter-match results, textinput's cursor-blink ticks, etc.) --
	// goes to whichever component is currently active. An early version of
	// this only forwarded tea.KeyMsg/tea.WindowSizeMsg explicitly, which
	// silently dropped list's own internal filter-result message and left
	// typed filter queries never actually narrowing the list.
	var cmd tea.Cmd
	switch m.stage {
	case stageMode:
		m.modeList, cmd = m.modeList.Update(msg)
	case stageTarget:
		m.procList, cmd = m.procList.Update(msg)
	case stageOutput, stageYAML, stageCommand:
		m.textIn, cmd = m.textIn.Update(msg)
	}
	return m, cmd
}

func (m model) View() string {
	switch m.stage {
	case stageMode:
		return m.modeList.View()
	case stageTarget:
		return m.procList.View()
	case stageOutput:
		return "Output path for the recorded test case:\n\n" + m.textIn.View() +
			"\n\n(enter to confirm, esc to quit)"
	case stageYAML:
		return "Path to the recorded YAML test case to replay:\n\n" + m.textIn.View() +
			"\n\n(enter to confirm, esc to quit)"
	case stageCommand:
		return fmt.Sprintf("Command to run (its Redis deps will be served from %s):\n\n%s\n\n(enter to confirm, esc to quit)",
			m.yamlPath, m.textIn.View())
	default:
		return ""
	}
}

// Run drives the interactive menu to completion and returns the assembled
// Result. ok is false if the user quit (Esc/Ctrl-C) before finishing a
// selection -- callers should treat that as "do nothing", not an error.
func Run() (Result, bool, error) {
	processes, err := ListProcesses()
	if err != nil {
		return Result{}, false, err
	}

	m := newModel(processes, findFirstYAML("."))
	final, err := tea.NewProgram(m).Run()
	if err != nil {
		return Result{}, false, err
	}

	fm, ok := final.(model)
	if !ok || fm.stage != stageDone {
		return Result{}, false, nil
	}
	return fm.result, true, nil
}
