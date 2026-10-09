//go:build !linux

package proxyserver

func processRunning(string) bool { return false }
