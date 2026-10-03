//go:build linux
// +build linux

package truststore

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/proxy/certmanager"
)

func userScopeSupportedPlatform() bool { return false }

type linuxTrustTool struct {
	anchorDir  string
	updateCmd  string
	anchorName string
}

// Overridable in tests.
var (
	lookPath         = exec.LookPath
	detectTrustTool  = detectLinuxTrustTool
	systemBundlePath = certmanager.SystemCABundlePath

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

func installPlatform(certPEM []byte, scope Scope) error {
	if scope == ScopeUser {
		return ErrUserScopeUnsupported
	}

	tool, err := detectTrustTool()
	if err != nil {
		return err
	}

	dest := filepath.Join(tool.anchorDir, tool.anchorName)

	tmp, cleanup, err := writeTempCert(certPEM)
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
	installed, err := parseCert(certPEM)
	if err != nil {
		return err
	}
	found, err := bundleContains(bundle, func(c *x509.Certificate) bool { return c.Equal(installed) })
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("installed the CA anchor to %s and ran %s, but %s does not contain the certificate: the trust tool did not read that directory", dest, tool.updateCmd, bundle)
	}
	return nil
}

func uninstallPlatform(_ string, scope Scope) error {
	if scope == ScopeUser {
		return ErrUserScopeUnsupported
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

// statusPlatform reports the certificate as trusted only when the system
// bundle holds it. An anchor file alone proves nothing: the update tool
// may never have read its directory. Without a bundle to check, the anchor
// is the best signal there is.
func statusPlatform(commonName string) (bool, bool, error) {
	tool, err := detectTrustTool()
	if err != nil {
		return false, false, nil
	}

	anchor := filepath.Join(tool.anchorDir, tool.anchorName)
	if _, err := os.Stat(anchor); err != nil {
		return false, false, nil // user scope is never trusted on Linux
	}

	bundle := systemBundlePath()
	if bundle == "" {
		return false, true, nil
	}
	found, err := bundleContains(bundle, func(c *x509.Certificate) bool { return c.Subject.CommonName == commonName })
	if err != nil {
		return false, false, err
	}
	if !found {
		log.Warnf("CA anchor %s is installed but %s does not contain it: the trust tool did not read that directory", anchor, bundle)
	}
	return false, found, nil
}

func parseCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM certificate to install")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	return cert, nil
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
