//go:build darwin

package trustca

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/safedep/pmg/proxy/certmanager"
)

func loginKeychainPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}

	return filepath.Join(home, "Library", "Keychains", "login.keychain-db"), nil
}

func installDarwinUserKeychain(certPath string) error {
	keychain, err := loginKeychainPath()
	if err != nil {
		return err
	}

	cmd := exec.Command(
		"security",
		"add-trusted-cert",
		"-d",
		"-r", "trustRoot",
		"-k", keychain,
		certPath,
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("trust proxy CA in login keychain: %w: %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}

func removeDarwinUserKeychain() error {
	hashes, err := FindDarwinProxyCAHashes()
	if err != nil {
		return err
	}

	if len(hashes) == 0 {
		return nil
	}

	var errs []error
	for _, hash := range hashes {
		cmd := exec.Command("security", "delete-certificate", "-Z", hash)
		out, err := cmd.CombinedOutput()
		if err != nil {
			errs = append(errs, fmt.Errorf("delete certificate %s: %w: %s", hash, err, strings.TrimSpace(string(out))))
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}

	return nil
}

func darwinUserTrustInstalled() bool {
	hashes, err := FindDarwinProxyCAHashes()
	return err == nil && len(hashes) > 0
}

func FindDarwinProxyCAHashes() ([]string, error) {
	cmd := exec.Command(
		"security",
		"find-certificate",
		"-c", certmanager.ProxyCACommonName,
		"-a",
		"-Z",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if bytes.Contains(out, []byte("could not be found")) {
			return nil, nil
		}

		return nil, fmt.Errorf("find proxy CA in keychain: %w: %s", err, strings.TrimSpace(string(out)))
	}

	var hashes []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "SHA-1 hash:") {
			continue
		}

		hash := strings.TrimSpace(strings.TrimPrefix(line, "SHA-1 hash:"))
		if hash != "" {
			hashes = append(hashes, hash)
		}
	}

	return hashes, nil
}
