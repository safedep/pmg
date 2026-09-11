//go:build unix

package setup

import (
	"testing"

	"github.com/safedep/pmg/errcodes"
	"github.com/stretchr/testify/assert"
)

// The sudo marker counts on Unix only, so the refusal has no Windows case.
func TestErrIfRunningUnderSudo(t *testing.T) {
	// sudo from a normal user is refused.
	withPrivilege(t, true)
	t.Setenv("SUDO_USER", "alice")
	assertUsefulCode(t, errIfRunningUnderSudo(), errcodes.PermissionDenied)

	// Genuine root is allowed.
	t.Setenv("SUDO_USER", "")
	assert.NoError(t, errIfRunningUnderSudo())

	// A user is allowed even when SUDO_USER is set.
	withPrivilege(t, false)
	t.Setenv("SUDO_USER", "alice")
	assert.NoError(t, errIfRunningUnderSudo())
}
