//go:build !windows

// Package proc decodes process termination status. It is a leaf utility shared
// by the execution layer (runner) and the PTY session, so neither has to
// reach through wrapper layers to learn how a child process ended.
package proc

import "syscall"

// SignalInfo reports whether a process was terminated by a signal, given the
// platform-specific status from (*exec.ExitError).Sys() / (*ptyx.ExitError).Sys().
// signum is the signal number; callers form the conventional exit code as 128+signum.
func SignalInfo(sys any) (signum int, signaled bool) {
	ws, ok := sys.(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		return 0, false
	}
	return int(ws.Signal()), true
}
