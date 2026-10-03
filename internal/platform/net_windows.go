package platform

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// Winsock has no ENFILE. The other three map one to one.
func isTransientAcceptError(err error) bool {
	for _, errno := range []syscall.Errno{windows.WSAEMFILE, windows.WSAECONNABORTED, windows.WSAENOBUFS} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}
