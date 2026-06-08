//go:build darwin
// +build darwin

package truststore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/dry/log"
)

const systemKeychainPath = "/Library/Keychains/System.keychain"

func userScopeSupportedPlatform() bool { return true }

func loginKeychainPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to resolve home dir: %w", err)
	}
	return filepath.Join(home, "Library", "Keychains", "login.keychain-db"), nil
}

func installPlatform(certPEM []byte, scope Scope) error {
	path, cleanup, err := writeTempCert(certPEM)
	if err != nil {
		return err
	}
	defer cleanup()

	var args []string
	runner := commandRunner
	if scope == ScopeSystem {
		args = []string{"add-trusted-cert", "-d", "-r", "trustRoot", "-k", systemKeychainPath, path}
		runner = runElevated
	} else {
		kc, err := loginKeychainPath()
		if err != nil {
			return err
		}
		args = []string{"add-trusted-cert", "-r", "trustRoot", "-k", kc, path}
	}

	if out, err := runner("security", args...); err != nil {
		return fmt.Errorf("security add-trusted-cert failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func uninstallPlatform(commonName string, scope Scope) error {
	// security delete-certificate removes a single match; loop until none remain
	// so a --force rotation that left two same-CN certs is fully cleaned.
	for i := 0; i < 16; i++ {
		args := []string{"delete-certificate", "-c", commonName}
		runner := commandRunner
		if scope == ScopeSystem {
			// -t clears trust settings; the keychain is a positional argument for
			// delete-certificate (it has no -k flag, unlike add-trusted-cert).
			args = append(args, "-t", systemKeychainPath)
			runner = runElevated
		}

		out, err := runner("security", args...)
		if err == nil {
			continue
		}

		// security reports no remaining match with "Unable to delete certificate
		// matching ..." (older/other paths use "Could not find"). Either marks the
		// terminal "nothing left to delete" case, so the loop ends successfully.
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "Unable to delete certificate matching") || strings.Contains(msg, "Could not find") {
			return nil
		}
		return fmt.Errorf("security delete-certificate failed: %w: %s", err, msg)
	}

	log.Warnf("security delete-certificate did not converge after 16 iterations; trust store cleanup may be incomplete")
	return nil
}

func statusPlatform(commonName string) (bool, bool, error) {
	lkc, err := loginKeychainPath()
	if err != nil {
		return false, certInKeychain(commonName, systemKeychainPath), nil
	}
	return certInKeychain(commonName, lkc), certInKeychain(commonName, systemKeychainPath), nil
}

func certInKeychain(commonName, keychain string) bool {
	args := []string{"find-certificate", "-c", commonName}
	if keychain != "" {
		args = append(args, keychain)
	}
	_, err := commandRunner("security", args...)
	return err == nil
}
