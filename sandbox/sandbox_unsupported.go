//go:build !darwin && !linux && !windows
// +build !darwin,!linux,!windows

package sandbox

import "fmt"

// newPlatformSandbox returns an error on unsupported platforms.
func newPlatformSandbox() (Sandbox, error) {
	return nil, fmt.Errorf("sandbox is not supported on this platform")
}
