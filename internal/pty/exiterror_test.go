//go:build !windows

package pty

import (
	"errors"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewExitError(t *testing.T) {
	underlying := errors.New("boom")

	t.Run("normal non-zero exit carries the raw code", func(t *testing.T) {
		e := newExitError(2, syscall.WaitStatus(2<<8), underlying)
		assert.Equal(t, 2, e.Code)
		assert.False(t, e.Signaled)
		assert.ErrorIs(t, e, underlying)
	})

	t.Run("signal termination resolves to 128+signum and marks signaled", func(t *testing.T) {
		e := newExitError(-1, syscall.WaitStatus(int(syscall.SIGINT)), underlying)
		assert.Equal(t, 128+int(syscall.SIGINT), e.Code)
		assert.True(t, e.Signaled)
	})

	t.Run("no wait status falls back to the provided code", func(t *testing.T) {
		e := newExitError(-1, nil, underlying)
		assert.Equal(t, -1, e.Code)
		assert.False(t, e.Signaled)
	})
}
