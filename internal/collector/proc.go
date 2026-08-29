package collector

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Comm returns the command name for pid by reading /proc/<pid>/comm.
// Returns "?" if the process has already exited or the name can't be read --
// this is cosmetic display data, not something callers should treat as fatal.
func Comm(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(data))
}

// findMappedLibrary scans /proc/<pid>/maps for a mapped shared object whose
// path contains substr (e.g. "libssl.so") and returns its on-disk path.
// This is how the traced process's actual loaded libssl is found -- reading
// the process's own memory map rather than assuming a system-wide path,
// since it works the same whether the process linked the system OpenSSL or
// a bundled/vendored one.
func findMappedLibrary(pid uint32, substr string) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return "", fmt.Errorf("open /proc/%d/maps: %w", pid, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, substr) {
			continue
		}
		fields := strings.Fields(line)
		path := fields[len(fields)-1]
		if strings.Contains(path, substr) {
			return path, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("read /proc/%d/maps: %w", pid, err)
	}
	return "", fmt.Errorf("no mapped library matching %q found for pid %d (process not linked against it, or not yet loaded)", substr, pid)
}
