//go:build !windows

package proxyserver

import (
	"fmt"
	"os"
	"syscall"
)

// listenStopRequest returns a nil channel on Unix because Run receives SIGTERM
// through os/signal.
func listenStopRequest() (<-chan struct{}, func(), error) {
	return nil, func() {}, nil
}

func requestStop(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find proxy process (pid %d): %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("send SIGTERM to proxy (pid %d): %w", pid, err)
	}
	return nil
}
