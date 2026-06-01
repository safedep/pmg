package runner

import (
	"errors"
	"fmt"
	"os/exec"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/proc"
	"github.com/safedep/pmg/internal/pty"
)

// ChildExitError marks a transparent passthrough: the wrapped package manager
// exited on its own. PMG attributes nothing to itself and mirrors the exit code,
// so the package manager's own output stands and PMG stays invisible.
type ChildExitError struct {
	Code     int    // child's exit code (or 128+signum for signal termination)
	Signaled bool   // true if terminated by a signal (Ctrl+C, SIGTERM, …)
	PMName   string // package manager name, for the dim one-liner
}

func (e *ChildExitError) Error() string {
	return fmt.Sprintf("%s exited with code %d", e.PMName, e.Code)
}
func (e *ChildExitError) ExitCode() int     { return e.Code }
func (e *ChildExitError) Transparent() bool { return true }
func (e *ChildExitError) IsSignaled() bool  { return e.Signaled }

// classify turns a package-manager execution error into either a transparent
// child exit or a visible PMG error, and is the only place the fork lives. It is
// pure: sandbox denials are persisted separately by the caller and never make a
// child's own non-zero exit loud — a restrictive policy routinely denies benign
// operations and causation cannot be inferred from a denial. Only a failure on
// PMG's side of the boundary (the tool never produced an exit status) is loud.
func classify(err error, pmName string) error {
	if err == nil {
		return nil
	}

	code, signaled, resolved := extractExit(err)
	return decideExit(err, code, signaled, resolved, pmName)
}

// extractExit pulls the exit code and signal status from a process error.
// resolved is false when the child never produced a real exit status (e.g. the
// binary failed to launch), which must surface as a visible PMG error.
func extractExit(err error) (code int, signaled bool, resolved bool) {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if signum, sig := proc.SignalInfo(exitErr.Sys()); sig {
			return 128 + signum, true, true
		}
		code = exitErr.ExitCode()
		return code, false, code >= 0
	}

	var ptyErr *pty.ExitError
	if errors.As(err, &ptyErr) {
		return ptyErr.Code, ptyErr.Signaled, ptyErr.Signaled || ptyErr.Code >= 0
	}

	return -1, false, false
}

func decideExit(err error, code int, signaled, resolved bool, pmName string) error {
	if !resolved {
		return visibleExecError(err)
	}
	return &ChildExitError{Code: code, Signaled: signaled, PMName: pmName}
}

// visibleExecError is the loud error for a genuine PMG-side failure: the package
// manager never produced an exit status (e.g. the binary could not be launched).
func visibleExecError(err error) error {
	return usefulerror.NewUsefulError().
		WithCode(errcodes.PackageManagerExecutionFailed).
		WithHumanError("Failed to execute package manager command").
		WithHelp("Check the package manager command and its arguments").
		Wrap(err)
}
