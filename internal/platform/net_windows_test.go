package platform

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
)

func TestIsTransientAcceptError(t *testing.T) {
	assert.True(t, IsTransientAcceptError(&net.OpError{Op: "accept", Err: windows.WSAEMFILE}))
	assert.True(t, IsTransientAcceptError(windows.WSAECONNABORTED))
	assert.True(t, IsTransientAcceptError(windows.WSAENOBUFS))
	assert.False(t, IsTransientAcceptError(windows.WSAEINVAL))
	assert.False(t, IsTransientAcceptError(net.ErrClosed))
	assert.False(t, IsTransientAcceptError(errors.New("listener gone")))
}
