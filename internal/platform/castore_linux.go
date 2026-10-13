//go:build linux

package platform

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/safedep/dry/log"
)

func caUserScopeSupported() bool { return false }

type linuxTrustTool struct {
	anchorDir  string
	updateCmd  string
	anchorName string
}

// Overridable in tests.
var (
	lookPath         = exec.LookPath
	detectTrustTool  = detectLinuxTrustTool
	systemBundlePath = SystemCABundlePath

	// p11-kit reads anchors from a distribution-specific directory. Fedora
	// and RHEL use the pki path. Arch ships the same update-ca-trust command
	// but its p11-kit scans /etc/ca-certificates/trust-source and never
	// /etc/pki, so an anchor there is silently ignored.
	pkiAnchorDir         = "/etc/pki/ca-trust/source/anchors"
	trustSourceAnchorDir = "/etc/ca-certificates/trust-source/anchors"
)

func detectLinuxTrustTool() (linuxTrustTool, error) {
	if _, err := lookPath("update-ca-certificates"); err == nil {
		return linuxTrustTool{
			anchorDir:  "/usr/local/share/ca-certificates",
			updateCmd:  "update-ca-certificates",
			anchorName: "pmg-proxy-ca.crt",
		}, nil
	}
	if _, err := lookPath("update-ca-trust"); err == nil {
		dir := pkiAnchorDir
		if dirExists(trustSourceAnchorDir) {
			dir = trustSourceAnchorDir
		}
		return linuxTrustTool{
			anchorDir:  dir,
			updateCmd:  "update-ca-trust",
			anchorName: "pmg-proxy-ca.crt",
		}, nil
	}
	return linuxTrustTool{}, fmt.Errorf("no supported trust tool (update-ca-certificates / update-ca-trust) found")
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func installCA(cert *x509.Certificate, scope CAScope) error {
	if scope == CAScopeUser {
		return ErrCAUserScopeUnsupported
	}

	tool, err := detectTrustTool()
	if err != nil {
		return err
	}

	dest := filepath.Join(tool.anchorDir, tool.anchorName)

	tmp, cleanup, err := writeTempCert(cert)
	if err != nil {
		return err
	}
	defer cleanup()

	// install(1) sets an explicit 0644 mode and creates the anchor dir if missing.
	if out, err := runElevated("install", "-m", "0644", "-D", tmp, dest); err != nil {
		return fmt.Errorf("failed to install CA anchor to %s: %w: %s", dest, err, strings.TrimSpace(string(out)))
	}

	if out, err := runElevated(tool.updateCmd); err != nil {
		return fmt.Errorf("%s failed: %w: %s", tool.updateCmd, err, strings.TrimSpace(string(out)))
	}

	// The update tool exits 0 even when it never read the anchor directory.
	// The bundle OpenSSL reads is the only proof that the trust took effect.
	bundle := systemBundlePath()
	if bundle == "" {
		return nil
	}
	found, err := bundleContains(bundle, cert.Equal)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("installed the CA anchor to %s and ran %s, but %s does not contain the certificate: the trust tool did not read that directory", dest, tool.updateCmd, bundle)
	}
	return nil
}

func uninstallCA(_ string, scope CAScope) error {
	if scope == CAScopeUser {
		return ErrCAUserScopeUnsupported
	}

	tool, err := detectTrustTool()
	if err != nil {
		return err
	}

	dest := filepath.Join(tool.anchorDir, tool.anchorName)
	if _, err := os.Stat(dest); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to stat CA anchor %s: %w", dest, err)
	}

	if out, err := runElevated("rm", "-f", dest); err != nil {
		return fmt.Errorf("failed to remove CA anchor %s: %w: %s", dest, err, strings.TrimSpace(string(out)))
	}

	if out, err := runElevated(tool.updateCmd); err != nil {
		return fmt.Errorf("%s failed: %w: %s", tool.updateCmd, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// caStores reports the certificate as trusted only when the system
// bundle holds it. The bundle also counts a CA that an administrator
// installed by another path. An anchor file alone proves nothing: the update
// tool may never have read its directory. Without a bundle to check, the
// anchor is the best signal there is. User scope is never trusted on Linux.
func caStores(cert *x509.Certificate) (bool, bool, error) {
	anchor := ""
	if tool, err := detectTrustTool(); err == nil {
		anchor = filepath.Join(tool.anchorDir, tool.anchorName)
	}

	// The anchor decides the result only when there is no bundle. Otherwise an
	// anchor that cannot be read must not hide a bundle that holds the CA.
	hasAnchor, anchorErr := fileExists(anchor)
	bundle := systemBundlePath()
	if bundle == "" {
		if anchorErr != nil {
			return false, false, anchorErr
		}
		if !hasAnchor {
			return false, false, nil
		}
		bundle = anchor
	} else if anchorErr != nil {
		log.Warnf("%v", anchorErr)
	}
	found, err := bundleContains(bundle, cert.Equal)
	if err != nil {
		return false, false, err
	}
	if !found && hasAnchor && bundle != anchor {
		log.Warnf("CA anchor %s is installed but %s does not contain it: the trust tool did not read that directory", anchor, bundle)
	}
	return false, found, nil
}

// fileExists reports a missing path as false. Any other stat error is
// returned, so a permission problem does not read as "not trusted".
func fileExists(path string) (bool, error) {
	if path == "" {
		return false, nil
	}
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat CA anchor %s: %w", path, err)
	}
	return true, nil
}

// verifyCATrusted checks the system scope, the only scope on Linux.
func verifyCATrusted(_ string, cert *x509.Certificate) error {
	_, system, err := caStores(cert)
	if err != nil {
		return err
	}
	if !system {
		return fmt.Errorf("%w: the system CA bundle does not hold the certificate", ErrCANotTrusted)
	}
	return nil
}

// bundleContains scans a PEM bundle for a certificate that match accepts. A
// block that does not parse is skipped, as OpenSSL skips it.
func bundleContains(bundle string, match func(*x509.Certificate) bool) (bool, error) {
	data, err := os.ReadFile(bundle)
	if err != nil {
		return false, fmt.Errorf("read system CA bundle %s: %w", bundle, err)
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return false, nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if match(cert) {
			return true, nil
		}
	}
}

func caBundleCandidates() []string {
	return []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
		"/etc/ssl/ca-bundle.pem",
		"/etc/ssl/cert.pem",
	}
}
