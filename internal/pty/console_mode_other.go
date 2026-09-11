//go:build !windows

package pty

// The Unix console keeps output post-processing in raw mode, and term.Restore
// puts the rest back. Nothing to undo.
func saveConsoleOutputMode() func() { return func() {} }
