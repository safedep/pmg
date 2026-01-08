//go:build windows
// +build windows

package sandbox

import "errors"

// newPlatformSandbox creates a platform-specific sandbox instance for Windows.
func newPlatformSandbox() (Sandbox, error) {
	return nil, errors.New("sandbox not yet implemented for Windows")
}
