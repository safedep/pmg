//go:build !windows

package proxyserver

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Daemonize re-execs the current binary with args (which must run the proxy in
// foreground mode), detached into its own session (Setsid), with child stdio
// redirected to cfg.LogPath. It waits up to cfg.ReadyTimeout for the child to
// write the state file and returns the running state. The caller owns the log
// path (its parent directory must exist); Daemonize fails if it cannot be
// opened.
func Daemonize(cfg ProxyDaemonConfig, statePath, exe string, args []string) (State, error) {
	logFile, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return State{}, fmt.Errorf("open daemon log %s: %w", cfg.LogPath, err)
	}

	defer func() { _ = logFile.Close() }()

	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		return State{}, fmt.Errorf("start daemon: %w", err)
	}
	if err := cmd.Process.Release(); err != nil {
		return State{}, fmt.Errorf("release daemon process: %w", err)
	}

	deadline := time.Now().Add(cfg.ReadyTimeout)
	for time.Now().Before(deadline) {
		if state, rerr := readState(statePath); rerr == nil && state.IsRunning() {
			return state, nil
		}
		time.Sleep(200 * time.Millisecond)
	}

	return State{}, fmt.Errorf("daemon did not become ready within %s; see %s", cfg.ReadyTimeout, cfg.LogPath)
}
