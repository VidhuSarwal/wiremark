package collector

import (
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
