//go:build unix

package setup

import (
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/truststore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestCertDirUsesSystemDirForPrivilegedSystemScope(t *testing.T) {
	cfg := config.Get()

	withPrivilege(t, true)
	t.Setenv("SUDO_USER", "alice")
	dir, err := certDir(cfg, truststore.ScopeSystem)
	require.NoError(t, err, "sudo with --system is the enforce flow")
	assert.Equal(t, config.SystemConfigDir(), dir)

	_, err = certDir(cfg, truststore.ScopeUser)
	assertUsefulCode(t, err, errcodes.PermissionDenied)

	t.Setenv("SUDO_USER", "")
	dir, err = certDir(cfg, truststore.ScopeUser)
	require.NoError(t, err)
	assert.Equal(t, cfg.ConfigDir(), dir)

	withPrivilege(t, false)
	dir, err = certDir(cfg, truststore.ScopeSystem)
	require.NoError(t, err, "an unprivileged --system install keeps the user keypair and elevates the trust step")
	assert.Equal(t, cfg.ConfigDir(), dir)
}
