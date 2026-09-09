//go:build unix

package proxyserver

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// IsRunning probes with Signal(0), which Windows does not support. The
// daemon is not supported on Windows, and its liveness check is its own
// issue.
func TestIsRunningCurrentProcess(t *testing.T) {
	s := State{PID: os.Getpid(), Addr: "127.0.0.1:1"}
	assert.True(t, s.IsRunning())
}
