//go:build unix

package platform

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsTransientAcceptError(t *testing.T) {
	assert.True(t, IsTransientAcceptError(&net.OpError{Op: "accept", Err: syscall.EMFILE}))
	assert.True(t, IsTransientAcceptError(syscall.ENFILE))
	assert.True(t, IsTransientAcceptError(syscall.ECONNABORTED))
	assert.True(t, IsTransientAcceptError(syscall.ENOBUFS))
	assert.False(t, IsTransientAcceptError(syscall.EINVAL))
	assert.False(t, IsTransientAcceptError(net.ErrClosed))
	assert.False(t, IsTransientAcceptError(errors.New("listener gone")))
}
