//go:build !windows
// +build !windows

package flows

import (
	"os/exec"
	"syscall"
)

func platformPauseProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	if err := cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		return err
	}

	return nil
}

func platformResumeProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	if err := cmd.Process.Signal(syscall.SIGCONT); err != nil {
		return err
	}

	return nil
}
