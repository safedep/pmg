//go:build !darwin && !linux && !windows
// +build !darwin,!linux,!windows

package truststore

import (
	"crypto/x509"
	"errors"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
)

func installPlatform(_ []byte, _ Scope) error     { return unsupportedPlatformError() }
func uninstallPlatform(_ string, _ Scope) error   { return unsupportedPlatformError() }
func statusPlatform(_ string) (bool, bool, error) { return false, false, unsupportedPlatformError() }
func userScopeSupportedPlatform() bool            { return false }

func caTrustedPlatform(_ string, _ *x509.Certificate) (bool, error) {
	return false, unsupportedPlatformError()
}

func unsupportedPlatformError() error {
	return usefulerror.NewUsefulError().
		WithCode(errcodes.UnsupportedPlatform).
		WithHumanError("trust store operations are not supported on this platform").
		WithHelp("Use PMG's default env-var trust injection, or install the CA manually").
		Wrap(errors.New("unsupported platform"))
}
