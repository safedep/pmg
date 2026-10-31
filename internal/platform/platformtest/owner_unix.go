//go:build unix

package platformtest

import (
	"os"
	"testing"

	"github.com/safedep/pmg/internal/platform"
)

// TrustCurrentUser makes platform.RequireSystemControlled accept the current
// user as an owner next to root until the test ends. A test cannot create a
// path that root owns, and the mode and link checks still apply.
func TrustCurrentUser(t *testing.T) {
	t.Helper()
	t.Cleanup(platform.TrustOwnerForTest(uint32(os.Getuid())))
}
