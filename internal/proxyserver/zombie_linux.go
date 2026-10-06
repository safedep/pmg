//go:build linux

package proxyserver

import (
	"fmt"
	"os"
	"strings"
)

// isZombie reports whether pid has exited and waits for its parent to reap
// it. A read or parse failure (for example /proc mounted with hidepid) reports
// false, so the caller keeps the Signal(0) result.
func isZombie(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	return zombieStat(string(data))
}

// zombieStat parses the state field of /proc/<pid>/stat. The field follows
// "(comm)", and comm can hold spaces and parentheses, so the parse starts after
// the last ')'.
func zombieStat(stat string) bool {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return false
	}
	fields := strings.Fields(stat[i+1:])
	if len(fields) == 0 {
		return false
	}
	return fields[0] == "Z" || fields[0] == "X"
}
