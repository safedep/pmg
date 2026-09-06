package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeLinkedWorktree(t *testing.T) (worktree, gitDir, commonDir string) {
	t.Helper()
	root := t.TempDir()
	commonDir = filepath.Join(root, "main", ".git")
	gitDir = filepath.Join(commonDir, "worktrees", "wt")
	worktree = filepath.Join(root, "wt")
	require.NoError(t, os.MkdirAll(gitDir, 0o755))
	require.NoError(t, os.MkdirAll(worktree, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: "+gitDir+"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "commondir"), []byte("../..\n"), 0o644))
	return worktree, gitDir, commonDir
}

func TestWorktreeGitDirs(t *testing.T) {
	t.Run("linked worktree", func(t *testing.T) {
		worktree, wantGit, wantCommon := writeLinkedWorktree(t)

		gitDir, commonDir, ok := WorktreeGitDirs(worktree)
		require.True(t, ok)
		assert.Equal(t, wantGit, gitDir)
		assert.Equal(t, wantCommon, commonDir)
	})

	t.Run("submodule has no commondir", func(t *testing.T) {
		root := t.TempDir()
		modDir := filepath.Join(root, "super", ".git", "modules", "lib")
		checkout := filepath.Join(root, "super", "lib")
		require.NoError(t, os.MkdirAll(modDir, 0o755))
		require.NoError(t, os.MkdirAll(checkout, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(checkout, ".git"), []byte("gitdir: ../.git/modules/lib\n"), 0o644))

		gitDir, commonDir, ok := WorktreeGitDirs(checkout)
		require.True(t, ok)
		assert.Equal(t, modDir, gitDir)
		assert.Equal(t, modDir, commonDir)
	})

	t.Run("normal checkout and non-repository", func(t *testing.T) {
		repo := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(repo, ".git"), 0o755))
		_, _, ok := WorktreeGitDirs(repo)
		assert.False(t, ok)

		_, _, ok = WorktreeGitDirs(t.TempDir())
		assert.False(t, ok)
	})
}

func TestApplyWorktreeGitDirs(t *testing.T) {
	worktree, gitDir, commonDir := writeLinkedWorktree(t)
	t.Chdir(worktree)

	t.Run("policy without .git write is untouched", func(t *testing.T) {
		policy := &SandboxPolicy{Filesystem: FilesystemPolicy{
			AllowWrite: []string{"${CWD}/node_modules/**"},
		}}
		assert.False(t, ApplyWorktreeGitDirs(policy, worktree))
		assert.Equal(t, []string{"${CWD}/node_modules/**"}, policy.Filesystem.AllowWrite)
	})

	t.Run("broad cwd write reaches the git directories with hooks and config denied", func(t *testing.T) {
		policy := &SandboxPolicy{Filesystem: FilesystemPolicy{
			AllowRead:  []string{"/"},
			AllowWrite: []string{"${CWD}/**"},
		}}
		require.True(t, ApplyWorktreeGitDirs(policy, worktree))

		assert.Contains(t, policy.Filesystem.AllowWrite, gitDir+"/**")
		assert.Contains(t, policy.Filesystem.AllowWrite, commonDir+"/**")
		assert.Contains(t, policy.Filesystem.DenyWrite, filepath.Join(commonDir, "hooks")+"/**")
		assert.Contains(t, policy.Filesystem.DenyWrite, filepath.Join(commonDir, "config"))
		assert.Contains(t, policy.Filesystem.DenyRead, filepath.Join(commonDir, "config"))
	})

	t.Run("git preset read opt-out on config is mirrored", func(t *testing.T) {
		policy := &SandboxPolicy{Filesystem: FilesystemPolicy{
			AllowRead:  []string{"${CWD}/.git/config"},
			AllowWrite: []string{"${CWD}/.git/**"},
		}}
		require.True(t, ApplyWorktreeGitDirs(policy, worktree))

		assert.Contains(t, policy.Filesystem.AllowRead, filepath.Join(commonDir, "config"))
		assert.NotContains(t, policy.Filesystem.DenyRead, filepath.Join(commonDir, "config"))
		assert.Contains(t, policy.Filesystem.DenyWrite, filepath.Join(commonDir, "config"))
	})
}
