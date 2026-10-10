//go:build unix

package util

import (
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/internal/platform/platformtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetMandatoryDenyPatternsWithoutHomeEnv(t *testing.T) {
	t.Run("anchors home denies at the user database home", func(t *testing.T) {
		t.Setenv("HOME", "")
		platformtest.StubPasswdHomeDir(t, "/home/fromdb", nil)

		r := mandatoryDenies(t, emptyOpts())
		assert.Contains(t, r.DenyRead, filepath.Join("/home/fromdb", GitHooksPath))
		assert.Contains(t, r.DenyWrite, filepath.Join("/home/fromdb", GitDirPath))
		assert.Contains(t, r.DenyWrite, filepath.Join("/home/fromdb", ".ssh"))
	})

	t.Run("fails closed when no home resolves", func(t *testing.T) {
		t.Setenv("HOME", "")
		platformtest.StubPasswdHomeDir(t, "", assert.AnError)

		r, err := GetMandatoryDenyPatterns(emptyOpts())
		assert.ErrorIs(t, err, assert.AnError)
		assert.Empty(t, r.DenyRead)
		assert.Empty(t, r.DenyWrite)
	})
}

func TestExpandVariablesWithoutHomeEnv(t *testing.T) {
	t.Run("uses the user database home", func(t *testing.T) {
		t.Setenv("HOME", "")
		platformtest.StubPasswdHomeDir(t, "/home/fromdb", nil)

		got, err := ExpandVariables("${HOME}/.npmrc")
		require.NoError(t, err)
		assert.Equal(t, "/home/fromdb/.npmrc", got)
	})

	t.Run("fails when no home resolves", func(t *testing.T) {
		t.Setenv("HOME", "")
		platformtest.StubPasswdHomeDir(t, "", assert.AnError)

		_, err := ExpandVariables("${HOME}/.npmrc")
		assert.ErrorIs(t, err, assert.AnError)
	})
}
