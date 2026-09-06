//go:build linux

package platform

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShimFilesystemRulesSkipUnopenablePaths(t *testing.T) {
	worktree := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: /elsewhere\n"), 0o644))

	rules := shimFilesystemRules([]landlockPathRule{
		{Path: worktree, Access: landlockReadAccess},
		{Path: filepath.Join(worktree, ".git", "config"), Access: landlockReadAccess},
		{Path: filepath.Join(worktree, "missing"), Access: landlockReadAccess},
	})

	assert.Len(t, rules, 1, "only the path that stats keeps a rule")
}
