package trustca

import (
	"fmt"
	"runtime"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy/certmanager"

)

// InstallProxyCA persists the PMG proxy root CA (if needed) and trusts it in the
// platform store when supported.
func InstallProxyCA() error {
	configDir := config.Get().ConfigDir()

	if _, err := certmanager.LoadOrCreatePersistedCA(configDir); err != nil {
		return err
	}

	certPath := certmanager.ProxyCARootCertPath(configDir)

	switch runtime.GOOS {
	case "darwin":
		return installDarwinUserKeychain(certPath)
	default:
		return fmt.Errorf("proxy CA keychain install is only supported on macOS (current OS: %s)", runtime.GOOS)
	}
}

// RemoveProxyCA removes persisted proxy CA files and revokes platform trust.
func RemoveProxyCA() error {
	configDir := config.Get().ConfigDir()

	switch runtime.GOOS {
	case "darwin":
		if err := removeDarwinUserKeychain(); err != nil {
			return err
		}
	default:
	}

	return certmanager.RemovePersistedCA(configDir)
}

// UserTrustInstalled reports whether the PMG proxy root CA is trusted in the user store.
func UserTrustInstalled() bool {
	switch runtime.GOOS {
	case "darwin":
		return darwinUserTrustInstalled()
	default:
		return false
	}
}
