//go:build windows

package pty

// Windows has no Unix-style terminal job control, so a process is never
// stopped for touching the console from the "background".
func isForegroundProcess(_ uintptr) bool {
	return true
}
