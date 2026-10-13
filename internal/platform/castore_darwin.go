//go:build darwin

package platform

import (
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/safedep/dry/log"
)

const systemKeychainPath = "/Library/Keychains/System.keychain"

func caUserScopeSupported() bool { return true }

func loginKeychainPath() (string, error) {
	home, err := UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to resolve home dir: %w", err)
	}
	return filepath.Join(home, "Library", "Keychains", "login.keychain-db"), nil
}

func installCA(cert *x509.Certificate, scope CAScope) error {
	path, cleanup, err := writeTempCert(cert)
	if err != nil {
		return err
	}
	defer cleanup()

	var args []string
	runner := commandRunner
	if scope == CAScopeSystem {
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

func uninstallCA(commonName string, scope CAScope) error {
	// security delete-certificate removes one match per run. The loop runs
	// until none remain, so two certificates with the same name both go.
	for i := 0; i < 16; i++ {
		args := []string{"delete-certificate", "-c", commonName}
		runner := commandRunner
		if scope == CAScopeSystem {
			// -t clears the trust settings. delete-certificate takes the keychain
			// as a positional argument. It has no -k flag.
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

		// security reports that no match remains with "Unable to delete
		// certificate matching" or, in older releases, "Could not find".
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "Unable to delete certificate matching") || strings.Contains(msg, "Could not find") {
			return nil
		}
		return fmt.Errorf("security delete-certificate failed: %w: %s", err, msg)
	}

	log.Warnf("security delete-certificate still found a certificate after 16 runs. The keychain can still hold a PMG CA.")
	return nil
}

// caStores reports which keychain holds this exact certificate. It
// compares the SHA-1 hash, so a different certificate with the same name in
// a keychain does not count.
func caStores(cert *x509.Certificate) (bool, bool, error) {
	system := certInKeychain(cert, systemKeychainPath)
	lkc, err := loginKeychainPath()
	if err != nil {
		return false, system, nil
	}
	return certInKeychain(cert, lkc), system, nil
}

// verifyCATrusted asks the OS to evaluate the certificate in certPath with the
// trust settings of the user and the system, as go does. A copy of the CA that
// is in a keychain but not trusted fails, and so does a different certificate
// with the same name. -l accepts a CA certificate as the leaf, -p ssl is the
// policy that go evaluates, and -L keeps the check off the network. Go used
// the same arguments when it verified roots with security(1).
func verifyCATrusted(certPath string, _ *x509.Certificate) error {
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

func caBundleCandidates() []string {
	return []string{
		"/opt/homebrew/etc/openssl@3/cert.pem",
		"/usr/local/etc/openssl@3/cert.pem",
		"/etc/ssl/cert.pem",
	}
}
