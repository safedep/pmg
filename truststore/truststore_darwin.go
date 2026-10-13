//go:build darwin
// +build darwin

package truststore

import (
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/platform"
)

const systemKeychainPath = "/Library/Keychains/System.keychain"

func userScopeSupportedPlatform() bool { return true }

func loginKeychainPath() (string, error) {
	home, err := platform.UserHomeDir()
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
		} else {
			// Without a keychain, delete-certificate searches the System keychain
			// too and fails there without root.
			kc, err := loginKeychainPath()
			if err != nil {
				return err
			}
			args = append(args, kc)
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

// statusPlatform reports which keychain holds this exact certificate. It
// compares the SHA-1 hash, so a different certificate with the same name in
// a keychain does not count.
func statusPlatform(cert *x509.Certificate) (bool, bool, error) {
	system := certInKeychain(cert, systemKeychainPath)
	lkc, err := loginKeychainPath()
	if err != nil {
		return false, system, nil
	}
	return certInKeychain(cert, lkc), system, nil
}

// caTrustedPlatform asks the OS to evaluate the certificate in certPath with the
// trust settings of the user and the system, as go does. A copy of the CA that
// is in a keychain but not trusted fails, and so does a different certificate
// with the same name. -l accepts a CA certificate as the leaf, -p ssl is the
// policy that go evaluates, and -L keeps the check off the network. Go used
// the same arguments when it verified roots with security(1).
func caTrustedPlatform(certPath string, _ *x509.Certificate) error {
	out, err := commandRunner("security", "verify-cert", "-p", "ssl", "-l", "-L", "-c", certPath)
	if err != nil {
		return fmt.Errorf("%w: security verify-cert %s: %s", ErrCANotTrusted, certPath, strings.TrimSpace(string(out)))
	}
	return nil
}

func certInKeychain(cert *x509.Certificate, keychain string) bool {
	out, err := commandRunner("security", "find-certificate", "-a", "-Z", "-c", cert.Subject.CommonName, keychain)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToUpper(string(out)), "SHA-1 HASH: "+thumbprint(cert))
}
