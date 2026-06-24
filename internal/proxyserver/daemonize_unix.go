//go:build !windows

package proxyserver

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/safedep/pmg/config"
)

// Daemonize re-execs the current binary with args (which must run the proxy in
// foreground mode), detached into its own session (Setsid), with child stdio
// redirected to a log file. It waits until the child writes the state file and
// returns the running state.
func Daemonize(cfg *config.RuntimeConfig, statePath string, args []string) (State, error) {
	exe, err := os.Executable()
	if err != nil {
		return State{}, fmt.Errorf("resolve executable: %w", err)
	}

	logPath := filepath.Join(cfg.CacheDir(), "proxy.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return State{}, fmt.Errorf("open daemon log %s: %w", logPath, err)
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

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if state, rerr := readState(statePath); rerr == nil && state.IsRunning() {
			return state, nil
		}
		time.Sleep(200 * time.Millisecond)
	}

	return State{}, fmt.Errorf("daemon did not become ready within timeout; see %s", logPath)
}
