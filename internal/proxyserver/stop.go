package proxyserver

import (
	"fmt"
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
}

// Stop signals the running proxy to terminate, waits for it to exit, and
// removes the state file. It returns a StopResult describing the run. The
// daemon flushes audit events to the cloud itself during shutdown (it, unlike
// this process, has no proxy env vars). Operational failures (no proxy running,
// signal errors) are returned as errors.
func Stop(statePath string) (StopResult, error) {
	state, err := readState(statePath)
	if err != nil {
		return StopResult{}, fmt.Errorf("no proxy state found — is the proxy running? (%w)", err)
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
	}, nil
}
