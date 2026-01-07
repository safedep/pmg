//go:build windows
// +build windows

package flows

import (
	"fmt"
	"os/exec"
)

// On Windows pausing/resuming a process is not supported.

func pauseProcess(_ *exec.Cmd) error {
	return fmt.Errorf("proxy is not supported on windows")
}

func resumeProcess(_ *exec.Cmd) error {
	return fmt.Errorf("proxy is not supported on windows")
}
