package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeGitDir(t *testing.T, dir string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "objects"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "refs"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644))
}

// writeLinkedWorktree lays out main/.git with a linked worktree wt, the way
// git worktree add does, including the back-pointer in worktrees/wt/gitdir.
func writeLinkedWorktree(t *testing.T) (worktree, gitDir, commonDir string) {
	t.Helper()
	root := t.TempDir()
	commonDir = filepath.Join(root, "main", ".git")
	gitDir = filepath.Join(commonDir, "worktrees", "wt")
	worktree = filepath.Join(root, "wt")
	writeGitDir(t, commonDir)
	require.NoError(t, os.MkdirAll(gitDir, 0o755))
	require.NoError(t, os.MkdirAll(worktree, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/wt\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: "+gitDir+"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "commondir"), []byte("../..\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "gitdir"), []byte(filepath.Join(worktree, ".git")+"\n"), 0o644))
	return worktree, gitDir, commonDir
}

// writeSubmodule lays out super/.git/modules/lib for the checkout super/lib,
// the way git submodule update does, with core.worktree pointing back.
func writeSubmodule(t *testing.T) (checkout, modDir string) {
	t.Helper()
	root := t.TempDir()
	modDir = filepath.Join(root, "super", ".git", "modules", "lib")
	checkout = filepath.Join(root, "super", "lib")
	writeGitDir(t, modDir)
	require.NoError(t, os.MkdirAll(checkout, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(checkout, ".git"), []byte("gitdir: ../.git/modules/lib\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(modDir, "config"), []byte("[core]\n\tbare = false\n\tworktree = ../../../lib\n"), 0o644))
	return checkout, modDir
}

func TestWorktreeGitDirs(t *testing.T) {
	t.Run("linked worktree", func(t *testing.T) {
		worktree, wantGit, wantCommon := writeLinkedWorktree(t)

		gitDir, commonDir, ok := WorktreeGitDirs(worktree)
		require.True(t, ok)
		assert.Equal(t, wantGit, gitDir)
		assert.Equal(t, wantCommon, commonDir)
	})

	t.Run("worktree of a bare repository", func(t *testing.T) {
		root := t.TempDir()
		bare := filepath.Join(root, "main.git")
		gitDir := filepath.Join(bare, "worktrees", "wt")
		worktree := filepath.Join(root, "wt")
		writeGitDir(t, bare)
		require.NoError(t, os.MkdirAll(gitDir, 0o755))
		require.NoError(t, os.MkdirAll(worktree, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/wt\n"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: "+gitDir+"\n"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(gitDir, "commondir"), []byte("../..\n"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(gitDir, "gitdir"), []byte(filepath.Join(worktree, ".git")+"\n"), 0o644))

		got, common, ok := WorktreeGitDirs(worktree)
		require.True(t, ok)
		assert.Equal(t, gitDir, got)
		assert.Equal(t, bare, common)
	})

	t.Run("submodule has no commondir", func(t *testing.T) {
		checkout, modDir := writeSubmodule(t)

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

// A pointer is repository content. None of these may turn into a grant.
func TestWorktreeGitDirsRejectsUntrustedPointers(t *testing.T) {
	t.Run("pointer at the home directory", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		writeGitDir(t, home)
		checkout := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(checkout, ".git"), []byte("gitdir: "+home+"\n"), 0o644))

		_, _, ok := WorktreeGitDirs(checkout)
		assert.False(t, ok)
	})

	t.Run("pointer at a directory that is not a git directory", func(t *testing.T) {
		target := t.TempDir()
		checkout := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(checkout, ".git"), []byte("gitdir: "+target+"\n"), 0o644))

		_, _, ok := WorktreeGitDirs(checkout)
		assert.False(t, ok)
	})

	t.Run("commondir that names another repository", func(t *testing.T) {
		worktree, gitDir, commonDir := writeLinkedWorktree(t)
		other := filepath.Join(filepath.Dir(filepath.Dir(commonDir)), "other", ".git")
		writeGitDir(t, other)
		require.NoError(t, os.WriteFile(filepath.Join(gitDir, "commondir"), []byte(other+"\n"), 0o644))

		_, _, ok := WorktreeGitDirs(worktree)
		assert.False(t, ok, "the git directory is not below the named common directory")
	})

	t.Run("worktree whose gitdir points elsewhere", func(t *testing.T) {
		worktree, gitDir, _ := writeLinkedWorktree(t)
		require.NoError(t, os.WriteFile(filepath.Join(gitDir, "gitdir"), []byte("/elsewhere/.git\n"), 0o644))

		_, _, ok := WorktreeGitDirs(worktree)
		assert.False(t, ok)
	})

	t.Run("pointer at another repository's worktree state", func(t *testing.T) {
		victim, victimGitDir, _ := writeLinkedWorktree(t)
		checkout := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(checkout, ".git"), []byte("gitdir: "+victimGitDir+"\n"), 0o644))

		_, _, ok := WorktreeGitDirs(checkout)
		assert.False(t, ok, "gitdir names %s, not %s", victim, checkout)
	})

	t.Run("submodule whose config names another worktree", func(t *testing.T) {
		checkout, modDir := writeSubmodule(t)
		require.NoError(t, os.WriteFile(filepath.Join(modDir, "config"), []byte("[core]\n\tworktree = ../../../other\n"), 0o644))

		_, _, ok := WorktreeGitDirs(checkout)
		assert.False(t, ok)
	})

	t.Run("submodule without core.worktree", func(t *testing.T) {
		checkout, modDir := writeSubmodule(t)
		require.NoError(t, os.Remove(filepath.Join(modDir, "config")))

		_, _, ok := WorktreeGitDirs(checkout)
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

	t.Run("pointer files are write denied", func(t *testing.T) {
		policy := &SandboxPolicy{Filesystem: FilesystemPolicy{
			AllowWrite: []string{"${CWD}/**", "${CWD}/.git"},
		}}
		require.True(t, ApplyWorktreeGitDirs(policy, worktree))

		assert.Contains(t, policy.Filesystem.DenyWrite, filepath.Join(worktree, ".git"))
		assert.Contains(t, policy.Filesystem.DenyWrite, filepath.Join(gitDir, "gitdir"))
		assert.Contains(t, policy.Filesystem.DenyWrite, filepath.Join(gitDir, "commondir"))
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
