package proxyserver

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"time"

	"github.com/safedep/dry/log"
)

const (
	stopPollInterval = 200 * time.Millisecond

	// stopWaitTimeout must exceed the daemon's worst-case shutdown (drain + cloud
	// flush), so we never read stale state or delete the state file while the
	// daemon is still flushing. Derived from the daemon's budget so the two can't
	// drift apart.
	stopWaitTimeout = daemonShutdownBudget + 15*time.Second
)

// ErrNoProxy means the state path has no state file, so no proxy runs from it.
var ErrNoProxy = errors.New("no proxy state found")

// StopResult carries the outcome of stopping the proxy so the caller can render
// a summary and decide whether to fail (e.g. on policy violations).
type StopResult struct {
	PID          int
	BlockedCount int
	// StateVerified is false when the final state could not be read after
	// shutdown (e.g. the proxy crashed), which callers may treat as fail-closed.
	StateVerified bool
	// CloudSync is the daemon's shutdown flush outcome (nil when cloud sync is
	// disabled), surfaced so the caller can report it.
	CloudSync *CloudSyncResult

	// Network is the daemon's network policy with its denials. nil when
	// the daemon had none.
	Network *NetworkState

	// Enforce is the kernel enforcement state. nil without --enforce.
	Enforce *EnforceState

	// RunID names the run in the event log. Observed is how many
	// destinations the proxy saw.
	RunID    string
	Observed int
}

// StopReport is the machine-readable stop result that `pmg proxy stop
// --report` writes. The GitHub Action job summary reads it.
type StopReport struct {
	Stopped       bool             `json:"stopped"`
	PID           int              `json:"pid,omitempty"`
	BlockedCount  int              `json:"blocked_count"`
	StateVerified bool             `json:"state_verified"`
	RunID         string           `json:"run_id,omitempty"`
	Observed      int              `json:"observed"`
	Network       *NetworkState    `json:"network,omitempty"`
	CloudSync     *CloudSyncResult `json:"cloud_sync,omitempty"`
	// Violation names what --fail-on-violation fails on. It is set whether
	// or not the flag is on.
	Violation string `json:"violation,omitempty"`
}

// Report is the result as a StopReport with the violation the caller
// computed.
func (r StopResult) Report(violation string) StopReport {
	return StopReport{
		Stopped:       true,
		PID:           r.PID,
		BlockedCount:  r.BlockedCount,
		StateVerified: r.StateVerified,
		RunID:         r.RunID,
		Observed:      r.Observed,
		Network:       r.Network,
		CloudSync:     r.CloudSync,
		Violation:     violation,
	}
}

// Stop signals the running proxy to terminate, waits for it to exit, and
// removes the state file. It returns a StopResult describing the run. The
// daemon flushes audit events to the cloud itself during shutdown (it, unlike
// this process, has no proxy env vars). Operational failures (no proxy running,
// signal errors) are returned as errors.
func Stop(statePath string) (StopResult, error) {
	state, err := readState(statePath)
	if errors.Is(err, fs.ErrNotExist) {
		return StopResult{}, fmt.Errorf("%w, is the proxy running? (%w)", ErrNoProxy, err)
	}
	if err != nil {
		return StopResult{}, fmt.Errorf("proxy state is unreadable: %w", err)
	}

	if !state.IsRunning() {
		if rerr := removeState(statePath); rerr != nil {
			log.Warnf("failed to remove proxy state file: %v", rerr)
		}
		return StopResult{}, fmt.Errorf("proxy process (pid %d) is not running; state file cleaned up", state.PID)
	}

	proc, err := os.FindProcess(state.PID)
	if err != nil {
		return StopResult{}, fmt.Errorf("find proxy process (pid %d): %w", state.PID, err)
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return StopResult{}, fmt.Errorf("send SIGTERM to proxy (pid %d): %w", state.PID, err)
	}

	deadline := time.Now().Add(stopWaitTimeout)
	exited := false
	for time.Now().Before(deadline) {
		if !state.IsRunning() {
			exited = true
			break
		}
		time.Sleep(stopPollInterval)
	}

	// If the daemon is still alive it is likely mid-flush. Do not read the state
	// (it is not final yet) or remove the file (the daemon still owns it).
	// Return an error so --fail-on-violation fails closed rather than reporting
	// a stale "0 blocked".
	if !exited {
		return StopResult{}, fmt.Errorf("proxy (pid %d) did not shut down within %s; leaving state file in place", state.PID, stopWaitTimeout)
	}

	final, readErr := readState(statePath)
	if rerr := removeState(statePath); rerr != nil {
		log.Warnf("failed to remove proxy state file: %v", rerr)
	}

	return StopResult{
		PID:           state.PID,
		BlockedCount:  final.BlockedCount,
		StateVerified: readErr == nil,
		CloudSync:     final.CloudSync,
		Network:       final.Network,
		Enforce:       final.Enforce,
		RunID:         final.RunID,
		Observed:      final.ObservedDestinations,
	}, nil
}
