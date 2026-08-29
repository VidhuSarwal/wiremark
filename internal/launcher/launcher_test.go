package launcher

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
)

// tm.Type sends literal rune characters, not key presses -- Enter, Esc, and
// arrow keys need an explicit tea.KeyMsg{Type: ...}, the same lesson
// internal/tui's tests already learned about Tab (see NOTES.md).
func enterKey() tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyEnter} }
func downKey() tea.KeyMsg  { return tea.KeyMsg{Type: tea.KeyDown} }
func escKey() tea.KeyMsg   { return tea.KeyMsg{Type: tea.KeyEsc} }

func equalArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// testProcesses is a small, deterministic process list -- real /proc
// contents aren't used in these tests, matching how internal/tui's tests
// inject synthetic events instead of driving a live trace.
func testProcesses() []Process {
	return []Process{{PID: 1234, Comm: "myapp"}}
}

func newTestLauncher(t *testing.T) *teatest.TestModel {
	t.Helper()
	m := newModel(testProcesses(), "test.yaml")
	return teatest.NewTestModel(t, m, teatest.WithInitialTermSize(120, 30))
}

func finalOf(t *testing.T, tm *teatest.TestModel) model {
	t.Helper()
	fm, ok := tm.FinalModel(t, teatest.WithFinalTimeout(2*time.Second)).(model)
	if !ok {
		t.Fatalf("FinalModel did not return a launcher model")
	}
	return fm
}

func TestLauncherTraceTUIFlow(t *testing.T) {
	tm := newTestLauncher(t)
	tm.Send(enterKey()) // accept the default (first) mode: Trace (interactive TUI)
	tm.Send(enterKey()) // accept the only listed process

	fm := finalOf(t, tm)
	want := []string{"trace", "--pid", "1234"}
	if !equalArgs(fm.result.Args, want) || !fm.result.NeedsSudo {
		t.Fatalf("result = %+v, want Args=%v NeedsSudo=true", fm.result, want)
	}
}

func TestLauncherTraceNoTUIFlow(t *testing.T) {
	tm := newTestLauncher(t)
	tm.Send(downKey())
	tm.Send(enterKey()) // Trace (plain text)
	tm.Send(enterKey())

	fm := finalOf(t, tm)
	want := []string{"trace", "--pid", "1234", "--no-tui"}
	if !equalArgs(fm.result.Args, want) || !fm.result.NeedsSudo {
		t.Fatalf("result = %+v, want Args=%v NeedsSudo=true", fm.result, want)
	}
}

func TestLauncherTraceTLSFlow(t *testing.T) {
	tm := newTestLauncher(t)
	tm.Send(downKey())
	tm.Send(downKey())
	tm.Send(enterKey()) // Trace with TLS
	tm.Send(enterKey())

	fm := finalOf(t, tm)
	want := []string{"trace", "--pid", "1234", "--tls"}
	if !equalArgs(fm.result.Args, want) || !fm.result.NeedsSudo {
		t.Fatalf("result = %+v, want Args=%v NeedsSudo=true", fm.result, want)
	}
}

func TestLauncherRecordFlow(t *testing.T) {
	tm := newTestLauncher(t)
	tm.Send(downKey())
	tm.Send(downKey())
	tm.Send(downKey())
	tm.Send(enterKey()) // Record a test case
	tm.Send(enterKey()) // pick the only process
	tm.Send(enterKey()) // accept the default output path

	fm := finalOf(t, tm)
	if len(fm.result.Args) != 5 || fm.result.Args[0] != "record" || fm.result.Args[1] != "--pid" ||
		fm.result.Args[2] != "1234" || fm.result.Args[3] != "-o" || !strings.HasPrefix(fm.result.Args[4], "recorded-") {
		t.Fatalf("result.Args = %v, want [record --pid 1234 -o recorded-*]", fm.result.Args)
	}
	if !fm.result.NeedsSudo {
		t.Fatal("record mode should need sudo (it loads BPF)")
	}
}

func TestLauncherRunFlow(t *testing.T) {
	tm := newTestLauncher(t)
	tm.Send(downKey())
	tm.Send(downKey())
	tm.Send(downKey())
	tm.Send(downKey())
	tm.Send(enterKey())     // Replay a test case (run)
	tm.Send(enterKey())     // accept the pre-filled YAML path ("test.yaml")
	tm.Type("./myapp arg1") // command to exec
	tm.Send(enterKey())

	fm := finalOf(t, tm)
	want := []string{"run", "--test", "test.yaml", "--", "./myapp", "arg1"}
	if !equalArgs(fm.result.Args, want) {
		t.Fatalf("result.Args = %v, want %v", fm.result.Args, want)
	}
	if fm.result.NeedsSudo {
		t.Fatal("run mode should not need sudo (no eBPF involved)")
	}
}

func TestLauncherEscAtModeStageQuits(t *testing.T) {
	tm := newTestLauncher(t)
	tm.Send(escKey())

	fm := finalOf(t, tm)
	if fm.stage != stageQuit {
		t.Fatalf("stage = %v, want stageQuit", fm.stage)
	}
	if fm.result.Args != nil {
		t.Fatalf("result.Args = %v, want nil (user quit without selecting)", fm.result.Args)
	}
}

func TestLauncherEscDuringCommandEntryQuits(t *testing.T) {
	tm := newTestLauncher(t)
	tm.Send(downKey())
	tm.Send(downKey())
	tm.Send(downKey())
	tm.Send(downKey())
	tm.Send(enterKey()) // Replay a test case (run)
	tm.Send(enterKey()) // accept pre-filled YAML path
	tm.Send(escKey())

	fm := finalOf(t, tm)
	if fm.stage != stageQuit {
		t.Fatalf("stage = %v, want stageQuit (esc mid-flow should still quit cleanly)", fm.stage)
	}
}
