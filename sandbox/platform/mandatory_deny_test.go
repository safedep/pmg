//go:build linux || darwin

package platform

import (
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/internal/platform/platformtest"
	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMandatoryDenies(t *testing.T) {
	t.Run("returns the expanded allow_read list", func(t *testing.T) {
		policy := &sandbox.SandboxPolicy{}
		policy.Filesystem.AllowRead = []string{"${TMPDIR}/x"}

		set, err := mandatoryDenies(policy)
		require.NoError(t, err)
		assert.NotEmpty(t, set.DenyWrite)
		require.Len(t, set.expandedAllowRead, 1)
		assert.Equal(t, "x", filepath.Base(set.expandedAllowRead[0]))
	})

	t.Run("fails closed when no home resolves", func(t *testing.T) {
		t.Setenv("HOME", "")
		platformtest.StubPasswdHomeDir(t, "", assert.AnError)

		_, err := mandatoryDenies(&sandbox.SandboxPolicy{})
		assert.ErrorIs(t, err, assert.AnError)
	})
}
