package proxyserver

// StatusInfo describes the proxy's current state for rendering by the caller.
type StatusInfo struct {
	Found   bool
	Running bool
	PID     int
	Addr    string
	CACert  string
}

// GetStatus reports the proxy status from the state file at statePath.
func GetStatus(statePath string) StatusInfo {
	state, err := readState(statePath)
	if err != nil {
		return StatusInfo{Found: false}
	}

	return StatusInfo{
		Found:   true,
		Running: state.IsRunning(),
		PID:     state.PID,
		Addr:    state.Addr,
		CACert:  state.CACertPath,
	}
}
