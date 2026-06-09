//go:build !windows

package pty

import (
	"golang.org/x/sys/unix"
)

// isForegroundProcess reports whether this process belongs to the terminal's
// foreground process group. A background job (e.g. `pmg npm install &`) still
// has the TTY on stdin/stdout, but changing terminal modes or reading from
// the TTY in a background process group triggers SIGTTOU/SIGTTIN, which stops
// the process.
func isForegroundProcess(fd uintptr) bool {
	foregroundPgrp, err := unix.IoctlGetInt(int(fd), unix.TIOCGPGRP)
	if err != nil {
		return false
	}

	return foregroundPgrp == unix.Getpgrp()
}
