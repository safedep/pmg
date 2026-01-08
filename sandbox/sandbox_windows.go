//go:build windows
// +build windows

package sandbox

import "errors"

// newPlatformSandbox creates a platform-specific sandbox instance for Windows.
// Currently not implemented - returns an error.
// Future implementations will use AppContainer or Job Objects.
func newPlatformSandbox() (Sandbox, error) {
	return nil, errors.New("sandbox not yet implemented for Windows (coming soon: AppContainer or Job Objects)")
}
