//go:build !darwin && !linux && !windows
// +build !darwin,!linux,!windows

package truststore

func installPlatform(_ []byte, _ Scope) error     { return unsupportedPlatformError() }
func uninstallPlatform(_ string, _ Scope) error   { return unsupportedPlatformError() }
func statusPlatform(_ string) (bool, bool, error) { return false, false, unsupportedPlatformError() }
func userScopeSupportedPlatform() bool            { return false }
