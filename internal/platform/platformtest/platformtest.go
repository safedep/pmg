// Package platformtest holds test seams of package platform that tests in
// other packages share.
package platformtest

import (
	"testing"

	"github.com/safedep/pmg/internal/platform"
)

// StubPasswdHomeDir makes platform.PasswdHomeDir return home and err until
// the test ends.
func StubPasswdHomeDir(t *testing.T, home string, err error) {
	t.Helper()
	orig := platform.PasswdHomeDir
	platform.PasswdHomeDir = func() (string, error) { return home, err }
	t.Cleanup(func() { platform.PasswdHomeDir = orig })
}

// StubSudo makes the process look like root that a user reached through sudo,
// with home as the home directory of that user, until the test ends.
func StubSudo(t *testing.T, home string) {
	t.Helper()
	origPrivileged := platform.IsPrivileged
	origHome := platform.SudoUserHomeDir
	platform.IsPrivileged = func() bool { return true }
	platform.SudoUserHomeDir = func() (string, error) { return home, nil }
	t.Setenv("SUDO_USER", "pmg-sudo-user")
	t.Cleanup(func() {
		platform.IsPrivileged = origPrivileged
		platform.SudoUserHomeDir = origHome
	})
}
