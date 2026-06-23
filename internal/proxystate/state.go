package proxystate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const stateFileName = "proxy-state.json"

type State struct {
	PID        int    `json:"pid"`
	Addr       string `json:"addr"`
	CACertPath string `json:"ca_cert_path"`
}

func StatePath(configDir string) string {
	return filepath.Join(configDir, stateFileName)
}

func Write(path string, s State) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal proxy state: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}

func Read(path string) (State, error) {
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

func Remove(path string) error {
	return os.Remove(path)
}

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
