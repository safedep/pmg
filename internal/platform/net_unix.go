//go:build unix

package platform

import (
	"errors"
	"syscall"
)

// The accept call fails with these while the process or the host is out of
// descriptors or buffers, and succeeds again once something frees them.
func isTransientAcceptError(err error) bool {
	for _, errno := range []syscall.Errno{syscall.EMFILE, syscall.ENFILE, syscall.ECONNABORTED, syscall.ENOBUFS} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}
