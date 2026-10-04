package proxyserver

import (
	"errors"
	"io/fs"
)

// StatusInfo describes the proxy's current state for rendering by the caller.
type StatusInfo struct {
	Found   bool
	Running bool
	PID     int
	Addr    string
	CACert  string
	Enforce *EnforceState

	// ConfigPath and ConfigSource are the file the daemon loaded, empty for
	// a state file an older daemon wrote.
	ConfigPath   string
	ConfigSource string

	// Unreadable is set when the state file exists but this user may not
	// read it. An enforcing daemon runs as root and owns the file.
	Unreadable bool
}

// GetStatus reports the proxy status from the state file at statePath.
func GetStatus(statePath string) StatusInfo {
	state, err := readState(statePath)
	if errors.Is(err, fs.ErrPermission) {
		return StatusInfo{Found: true, Unreadable: true}
	}
	if err != nil {
		return StatusInfo{Found: false}
	}

	return StatusInfo{
		Found:   true,
		Running: state.IsRunning(),
		PID:     state.PID,
		Addr:    state.Addr,
		CACert:  state.CACertPath,
		Enforce: state.Enforce,

		ConfigPath:   state.ConfigPath,
		ConfigSource: state.ConfigSource,
	}
}
