//go:build !windows

package config

// programDataDir is a Windows location.
func programDataDir() string { return "" }
