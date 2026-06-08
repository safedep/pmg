//go:build linux
// +build linux

package truststore

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func userScopeSupportedPlatform() bool { return false }

type linuxTrustTool struct {
	anchorDir  string
	updateCmd  string
	anchorName string
}

// lookPath is overridable in tests.
var lookPath = exec.LookPath

// detectTrustTool is overridable in tests so anchorDir points to a temp dir.
var detectTrustTool = detectLinuxTrustTool

func detectLinuxTrustTool() (linuxTrustTool, error) {
	if _, err := lookPath("update-ca-certificates"); err == nil {
		return linuxTrustTool{
			anchorDir:  "/usr/local/share/ca-certificates",
			updateCmd:  "update-ca-certificates",
			anchorName: "pmg-proxy-ca.crt",
		}, nil
	}
	if _, err := lookPath("update-ca-trust"); err == nil {
		return linuxTrustTool{
			anchorDir:  "/etc/pki/ca-trust/source/anchors",
			updateCmd:  "update-ca-trust",
			anchorName: "pmg-proxy-ca.crt",
		}, nil
	}
	return linuxTrustTool{}, fmt.Errorf("no supported trust tool (update-ca-certificates / update-ca-trust) found")
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

func statusPlatform(_ string) (bool, bool, error) {
	tool, err := detectTrustTool()
	if err != nil {
		return false, false, nil
	}

	dest := filepath.Join(tool.anchorDir, tool.anchorName)
	if _, err := os.Stat(dest); err == nil {
		return false, true, nil // user scope is never trusted on Linux
	}
	return false, false, nil
}
