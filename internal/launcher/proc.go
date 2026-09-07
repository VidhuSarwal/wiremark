// Package launcher provides an interactive TUI menu for picking a mode
// (trace/record/run) and a target (PID, output path, or YAML+command), then
// handing back the assembled command-line args for cmd/wiremark to exec.
package launcher

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Process is one running process, for the target-picker list.
type Process struct {
	PID  uint32
	Comm string
}

// ListProcesses reads /proc/*/comm for every currently running process,
// sorted by PID. A process that exits between the directory listing and its
// own comm read is silently skipped -- this is a point-in-time snapshot for
// a human to pick from, not something correctness depends on.
func ListProcesses() ([]Process, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var procs []Process
	for _, e := range entries {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue // not a PID directory (e.g. "self", "net", ...)
		}
		data, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue // process exited since ReadDir, or unreadable
		}
		procs = append(procs, Process{PID: uint32(pid), Comm: strings.TrimSpace(string(data))})
	}

	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	return procs, nil
}

// findFirstYAML returns the first *.yaml/*.yml file in dir (lexical order),
// for pre-filling the run-mode YAML path prompt. Returns "" if none found or
// dir can't be read -- this is a convenience default, not a requirement, so
// callers should treat both as "no suggestion" rather than an error.
func findFirstYAML(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if ext := filepath.Ext(e.Name()); ext == ".yaml" || ext == ".yml" {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return names[0]
}
