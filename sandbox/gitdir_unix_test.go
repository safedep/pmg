//go:build unix

package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/internal/platform/platformtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorktreeGitDirsWithoutHomeEnv(t *testing.T) {
	t.Run("rejects a pointer at the user database home", func(t *testing.T) {
		home := t.TempDir()
		writeGitDir(t, home)
		t.Setenv("HOME", "")
		platformtest.StubPasswdHomeDir(t, home, nil)
		checkout := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(checkout, ".git"), []byte("gitdir: "+home+"\n"), 0o644))

		_, _, ok := WorktreeGitDirs(checkout)
		assert.False(t, ok)
	})

	t.Run("rejects every pointer when no home resolves", func(t *testing.T) {
		worktree, _, _ := writeLinkedWorktree(t)
		t.Setenv("HOME", "")
		platformtest.StubPasswdHomeDir(t, "", assert.AnError)

		_, _, ok := WorktreeGitDirs(worktree)
		assert.False(t, ok)
	})
}
