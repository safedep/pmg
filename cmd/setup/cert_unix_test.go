//go:build unix

package setup

import (
	"testing"

	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The sudo marker counts on Unix only, so these rows have no Windows case.
func TestKeypairLayoutUnderSudo(t *testing.T) {
	user, system := t.TempDir(), t.TempDir()
	withPrivilege(t, true)
	t.Setenv("SUDO_USER", "alice")

	enforcing := keypairLayout{user: user, system: system}
	dir, err := enforcing.installDir(platform.CAScopeSystem)
	require.NoError(t, err, "sudo with --system is the enforce flow")
	assert.Equal(t, system, dir)

	_, err = enforcing.installDir(platform.CAScopeUser)
	assertUsefulCode(t, err, errcodes.PermissionDenied)

	noProxy := keypairLayout{user: user, legacy: system}
	_, err = noProxy.installDir(platform.CAScopeSystem)
	assertUsefulCode(t, err, errcodes.PermissionDenied)
	dirs, err := noProxy.purgeDirs(platform.CAScopeSystem)
	require.NoError(t, err, "macOS needs sudo to delete the root-owned legacy keypair")
	assert.Equal(t, []string{system}, dirs, "sudo purges the legacy keypair, not the user's")
	assert.NotContains(t, noProxy.refuseSudo().Error(), "enforcing proxy",
		"the help must not name a command that this platform refuses")

	t.Setenv("SUDO_USER", "")
	assert.NoError(t, enforcing.refuseSudo(), "genuine root is allowed")

	withPrivilege(t, false)
	t.Setenv("SUDO_USER", "alice")
	assert.NoError(t, enforcing.refuseSudo(), "a user is allowed even when SUDO_USER is set")
}
