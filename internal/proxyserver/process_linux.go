//go:build linux

package proxyserver

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// processRunning reports whether a process with the given command name
// exists. It reads /proc/<pid>/comm, which needs no extra privilege.
func processRunning(name string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) == name {
			return true
		}
	}
	return false
}
