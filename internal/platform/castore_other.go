//go:build !darwin && !linux && !windows

package platform

import (
	"crypto/x509"
	"errors"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
)

func installCA(_ *x509.Certificate, _ TrustScope) error { return unsupportedPlatformError() }
func uninstallCA(_ string, _ TrustScope) error          { return unsupportedPlatformError() }
func caStores(_ *x509.Certificate) (bool, bool, error) {
	return false, false, unsupportedPlatformError()
}
func caUserScopeSupported() bool { return false }

func verifyCATrusted(_ string, _ *x509.Certificate) error {
	return unsupportedPlatformError()
}

func unsupportedPlatformError() error {
	return usefulerror.NewUsefulError().
		WithCode(errcodes.UnsupportedPlatform).
		WithHumanError("trust store operations are not supported on this platform").
		WithHelp("Use PMG's default env-var trust injection, or install the CA manually").
		Wrap(errors.New("unsupported platform"))
}

func caBundleCandidates() []string { return nil }
