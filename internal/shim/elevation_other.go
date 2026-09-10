//go:build !windows

package shim

// ProcessIsElevated is a Windows concept. Unix asks for root instead.
func ProcessIsElevated() bool { return false }
