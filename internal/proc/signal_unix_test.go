//go:build !windows

package proc

import (
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignalInfo(t *testing.T) {
	tests := []struct {
		name         string
		sys          any
		wantSignum   int
		wantSignaled bool
	}{
		{
			name:         "SIGINT terminated process",
			sys:          syscall.WaitStatus(int(syscall.SIGINT)),
			wantSignum:   int(syscall.SIGINT),
			wantSignaled: true,
		},
		{
			name:         "SIGTERM terminated process",
			sys:          syscall.WaitStatus(int(syscall.SIGTERM)),
			wantSignum:   int(syscall.SIGTERM),
			wantSignaled: true,
		},
		{
			name:         "normal exit code 2 is not signaled",
			sys:          syscall.WaitStatus(2 << 8),
			wantSignum:   0,
			wantSignaled: false,
		},
		{
			name:         "nil status is not signaled",
			sys:          nil,
			wantSignum:   0,
			wantSignaled: false,
		},
		{
			name:         "non-WaitStatus value is not signaled",
			sys:          "not a wait status",
			wantSignum:   0,
			wantSignaled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signum, signaled := SignalInfo(tt.sys)
			assert.Equal(t, tt.wantSignaled, signaled)
			assert.Equal(t, tt.wantSignum, signum)
		})
	}
}
