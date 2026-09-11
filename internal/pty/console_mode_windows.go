//go:build windows

package pty

import (
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
func saveConsoleOutputMode() func() {
	type saved struct {
		handle windows.Handle
		mode   uint32
	}
	var modes []saved
	for _, f := range []*os.File{os.Stdout, os.Stderr} {
		handle := windows.Handle(f.Fd())
		var mode uint32
		if windows.GetConsoleMode(handle, &mode) == nil {
			modes = append(modes, saved{handle: handle, mode: mode})
		}
	}
	return func() {
		for _, s := range modes {
			if s.mode&disableNewlineAutoReturn != 0 {
				continue
			}
			var current uint32
			if windows.GetConsoleMode(s.handle, &current) != nil {
				continue
			}
			_ = windows.SetConsoleMode(s.handle, current&^disableNewlineAutoReturn)
		}
	}
}
