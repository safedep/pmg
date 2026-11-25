//go:build unix

package platform

import (
	"errors"
	"os"
	"syscall"
)

func parentProcessName() (string, error) { return "", errors.ErrUnsupported }

func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil && !isZombieProcess(pid)
}
