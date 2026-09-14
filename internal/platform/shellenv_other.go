//go:build !darwin

package platform

func defaultShell() string { return "bash" }

func bashUsesLoginShell() bool { return false }
