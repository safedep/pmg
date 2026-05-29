package ui

import (
	"errors"
	"fmt"
	"os"
)

// transparentExit is satisfied by *runner.ChildExitError without importing it.
// It marks a wrapped package manager that exited on its own, which PMG passes
// through transparently rather than dressing up as a PMG-level failure.
type transparentExit interface {
	error
	Transparent() bool
	ExitCode() int
	IsSignaled() bool
}

// exitDecision is the pure outcome of inspecting a command error: whether to
// pass through transparently, what code to mirror, and the dim notice (if any).
type exitDecision struct {
	transparent bool
	notice      bool
	code        int
	message     string
}

// classifyExit decides how to terminate for a command error. It is pure so the
// policy is unit-testable without os.Exit. transparent=false means fall through
// to the loud ErrorExit path. The notice is suppressed for signal exits (the
// user initiated the interrupt) and in silent mode.
func classifyExit(err error) exitDecision {
	var te transparentExit
	if !errors.As(err, &te) || !te.Transparent() {
		return exitDecision{}
	}

	d := exitDecision{transparent: true, code: te.ExitCode()}
	if !te.IsSignaled() && verbosityLevel != VerbosityLevelSilent {
		d.notice = true
		// The pmg: self-reference quietly signals PMG wrapped the run without
		// the loud error box — a subtle sense of protection.
		d.message = "↳ pmg: " + te.Error()
	}
	return d
}

// ExitFromCommandError is the single exit point for package-manager commands. A
// child that exited on its own is mirrored transparently; everything else keeps
// the visible PMG error framing.
func ExitFromCommandError(err error) {
	if err == nil {
		return
	}

	if d := classifyExit(err); d.transparent {
		ClearStatus()
		if d.notice {
			fmt.Println(Colors.Dim(d.message))
		}
		os.Exit(d.code)
	}

	ErrorExit(err)
}
