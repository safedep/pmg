//go:build !linux

package netenforce

import "github.com/safedep/pmg/internal/platform"

func newPlatformEnforcer() (Enforcer, error) {
	return nil, &unsupportedError{goos: platform.OSName()}
}

// unsupportedError names the platform and unwraps to ErrUnsupported.
type unsupportedError struct {
	goos string
}

func (e *unsupportedError) Error() string {
	return "network enforcement is not supported on " + e.goos + ", it needs Linux"
}

func (e *unsupportedError) Unwrap() error { return ErrUnsupported }
