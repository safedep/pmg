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
