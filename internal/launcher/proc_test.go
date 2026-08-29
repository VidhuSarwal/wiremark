package launcher

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListProcessesFindsSelf(t *testing.T) {
	procs, err := ListProcesses()
	if err != nil {
		t.Fatalf("ListProcesses: %v", err)
	}
	if len(procs) == 0 {
		t.Fatal("ListProcesses returned no processes on a live system")
	}

	self := uint32(os.Getpid())
	var found bool
	for _, p := range procs {
		if p.PID == self {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListProcesses did not include this test process's own PID %d", self)
	}
}

func TestFindFirstYAMLPicksLexicallyFirst(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"zebra.yaml", "apple.yml", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}
	if got := findFirstYAML(dir); got != "apple.yml" {
		t.Errorf("findFirstYAML = %q, want %q", got, "apple.yml")
	}
}

func TestFindFirstYAMLEmptyWhenNoneFound(t *testing.T) {
	dir := t.TempDir()
	if got := findFirstYAML(dir); got != "" {
		t.Errorf("findFirstYAML = %q, want \"\"", got)
	}
}
