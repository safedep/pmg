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
	type saved struct {
		name   string
		handle windows.Handle
		mode   uint32
	}
	var modes []saved
	for _, output := range []struct {
		name string
		file *os.File
	}{
		{name: "stdout", file: os.Stdout},
		{name: "stderr", file: os.Stderr},
	} {
		handle := windows.Handle(output.file.Fd())
		var mode uint32
		if windows.GetConsoleMode(handle, &mode) == nil {
			modes = append(modes, saved{name: output.name, handle: handle, mode: mode})
		}
	}
	return func() error {
		var errs []error
		for _, s := range modes {
			if s.mode&disableNewlineAutoReturn != 0 {
				continue
			}
			var current uint32
			if err := windows.GetConsoleMode(s.handle, &current); err != nil {
				errs = append(errs, fmt.Errorf("failed to read %s console mode: %w", s.name, err))
				continue
			}
			if err := windows.SetConsoleMode(s.handle, current&^disableNewlineAutoReturn); err != nil {
				errs = append(errs, fmt.Errorf("failed to restore %s console mode: %w", s.name, err))
			}
		}
		return errors.Join(errs...)
	}
}
