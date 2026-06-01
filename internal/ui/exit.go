package ui

import (
	"errors"
	"fmt"
	"os"
)

// transparentExit is satisfied by *runner.ChildExitError without importing it.
type transparentExit interface {
	error
	Transparent() bool
	ExitCode() int
	IsSignaled() bool
}

type exitDecision struct {
	transparent bool
	notice      bool
	code        int
	message     string
}

// classifyExit is the pure decision behind ExitFromCommandError. The notice is
// suppressed for signal exits (the user initiated the interrupt) and in silent
// mode.
func classifyExit(err error) exitDecision {
	var te transparentExit
	if !errors.As(err, &te) || !te.Transparent() {
		return exitDecision{}
	}

	d := exitDecision{transparent: true, code: te.ExitCode()}
	if !te.IsSignaled() && verbosityLevel != VerbosityLevelSilent {
		d.notice = true
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
			fmt.Fprintln(os.Stderr, Colors.Dim(d.message))
		}
		os.Exit(d.code)
	}

	ErrorExit(err)
}
