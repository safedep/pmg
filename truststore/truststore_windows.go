//go:build windows
// +build windows

package truststore

import (
	"fmt"
	"strings"
)

func userScopeSupportedPlatform() bool { return true }

func installPlatform(certPEM []byte, scope Scope) error {
	path, cleanup, err := writeTempCert(certPEM)
	if err != nil {
		return err
	}
	defer cleanup()

	args := []string{}
	if scope == ScopeUser {
		args = append(args, "-user")
	}
	args = append(args, "-addstore", "Root", path)

	if out, err := commandRunner("certutil", args...); err != nil {
		return fmt.Errorf("certutil -addstore failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func uninstallPlatform(commonName string, scope Scope) error {
	args := []string{}
	if scope == ScopeUser {
		args = append(args, "-user")
	}
	args = append(args, "-delstore", "Root", commonName)

	if out, err := commandRunner("certutil", args...); err != nil {
		msg := strings.TrimSpace(string(out))
		lower := strings.ToLower(msg)
		if strings.Contains(lower, "cannot find") || strings.Contains(msg, "0x80092004") {
			return nil
		}
		return fmt.Errorf("certutil -delstore failed: %w: %s", err, msg)
	}
	return nil
}

func statusPlatform(commonName string) (bool, bool, error) {
	return certInWindowsStore(commonName, true), certInWindowsStore(commonName, false), nil
}

func certInWindowsStore(commonName string, userScope bool) bool {
	args := []string{}
	if userScope {
		args = append(args, "-user")
	}
	args = append(args, "-store", "Root", commonName)

	_, err := commandRunner("certutil", args...)
	return err == nil
}
