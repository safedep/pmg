package proxyserver

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
)

const (
	stopPollInterval = 200 * time.Millisecond
	stopPollTimeout  = 10 * time.Second
)

// StopResult carries the outcome of stopping the proxy so the caller can render
// a summary and decide whether to fail (e.g. on policy violations).
type StopResult struct {
	PID          int
	BlockedCount int
	// StateVerified is false when the final state could not be read after
	// shutdown (e.g. the proxy crashed), which callers may treat as fail-closed.
	StateVerified bool
}

// Stop signals the running proxy to terminate, waits for it to exit, flushes
// pending audit events to the cloud, and removes the state file. It returns a
// StopResult describing the run. Operational failures (no proxy running, signal
// errors) are returned as errors.
func Stop(ctx context.Context, cfg *config.RuntimeConfig, statePath string) (StopResult, error) {
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

	deadline := time.Now().Add(stopPollTimeout)
	for time.Now().Before(deadline) {
		if !state.IsRunning() {
			break
		}
		time.Sleep(stopPollInterval)
	}

	final, readErr := readState(statePath)
	if rerr := removeState(statePath); rerr != nil {
		log.Warnf("failed to remove proxy state file: %v", rerr)
	}

	// Flush events to cloud before the (potentially ephemeral) host goes away.
	if ferr := flushCloudEvents(ctx, cfg); ferr != nil {
		log.Warnf("cloud event flush failed: %v", ferr)
	}

	return StopResult{
		PID:           state.PID,
		BlockedCount:  final.BlockedCount,
		StateVerified: readErr == nil,
	}, nil
}
