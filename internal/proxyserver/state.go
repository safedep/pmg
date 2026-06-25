package proxyserver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const stateFileName = "proxy-state.json"

// State is the on-disk record of a running persistent proxy. It is written by
// the daemon and read by the stop/env/status commands.
type State struct {
	PID          int    `json:"pid"`
	Addr         string `json:"addr"`
	CACertPath   string `json:"ca_cert_path"`
	BlockedCount int    `json:"blocked_count"`

	// CloudSync records the daemon's shutdown cloud flush so `pmg proxy stop`
	// can report the outcome. The daemon's own logs go to proxy.log (and are
	// suppressed without --debug), so the state file is how the result reaches
	// the stop process. nil when cloud sync is disabled.
	CloudSync *CloudSyncResult `json:"cloud_sync,omitempty"`
}

// CloudSyncResult is the outcome of the daemon's shutdown flush to SafeDep Cloud.
type CloudSyncResult struct {
	Synced int    `json:"synced"`
	Error  string `json:"error,omitempty"`
}

func stateFilePath(dir string) string {
	return filepath.Join(dir, stateFileName)
}

func writeState(path string, s State) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal proxy state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create proxy state dir: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}

func readState(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}, fmt.Errorf("read proxy state: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, fmt.Errorf("unmarshal proxy state: %w", err)
	}
	return s, nil
}

func removeState(path string) error {
	return os.Remove(path)
}

// IsRunning reports whether the recorded PID is a live process.
func (s State) IsRunning() bool {
	if s.PID <= 0 {
		return false
	}
	proc, err := os.FindProcess(s.PID)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// ResolveStatePath returns the effective state file path: the flag override
// when set, otherwise <cacheDir>/proxy-state.json.
func ResolveStatePath(flag, cacheDir string) string {
	if flag != "" {
		return flag
	}
	return stateFilePath(cacheDir)
}
