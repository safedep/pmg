//go:build !windows
// +build !windows

package flows

import (
	"fmt"
	"os/exec"
	"syscall"
)

func pauseProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if err := cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		return fmt.Errorf("failed to pause process: %w", err)
	}
	return nil
}

func resumeProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if err := cmd.Process.Signal(syscall.SIGCONT); err != nil {
		return fmt.Errorf("failed to resume process: %w", err)
	}
	return nil
}
