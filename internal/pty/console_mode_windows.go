//go:build windows

package pty

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// ptyx sets this on stdout and stderr so the child's VT stream is not
// translated twice, and leaves it set. A `\n` PMG prints after the session
// then moves down without a carriage return, and the report staircases.
const disableNewlineAutoReturn = 0x0008

// saveConsoleOutputMode returns a function that clears the newline flag on
// stdout and stderr again, when it was clear before the session. The other
// flags stay as they are at that time.
func saveConsoleOutputMode() func() error {
	restoreStdout := saveOutputMode("stdout", os.Stdout)
	restoreStderr := saveOutputMode("stderr", os.Stderr)

	return func() error {
		return errors.Join(restoreStdout(), restoreStderr())
	}
}

func saveOutputMode(name string, output *os.File) func() error {
	handle := windows.Handle(output.Fd())
	var original uint32
	if err := windows.GetConsoleMode(handle, &original); err != nil || original&disableNewlineAutoReturn != 0 {
		return func() error { return nil }
	}

	return func() error {
		var current uint32
		if err := windows.GetConsoleMode(handle, &current); err != nil {
			return fmt.Errorf("failed to read %s console mode: %w", name, err)
		}
		if err := windows.SetConsoleMode(handle, current&^disableNewlineAutoReturn); err != nil {
			return fmt.Errorf("failed to restore %s console mode: %w", name, err)
		}
		return nil
	}
}
