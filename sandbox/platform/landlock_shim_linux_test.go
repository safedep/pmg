//go:build linux

package platform

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
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

// A missing socket must fail closed on Landlock ABI 9: the shim adds no rule
// for it, but the ruleset still handles resolve-unix, so the kernel refuses
// the connect. A rule on a socket keeps the right that a regular file rule
// would also keep.
func TestShimFilesystemRules_UnixConnect(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "s.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, listener.Close()) })
	missing := filepath.Join(dir, "missing.sock")

	policy := &landlockExecPolicy{FilesystemRules: []landlockPathRule{
		{Path: socket, Access: uint64(llsyscall.AccessFSResolveUnix)},
		{Path: missing, Access: uint64(llsyscall.AccessFSResolveUnix)},
	}}

	rules := shimFilesystemRules(policy.FilesystemRules)
	require.Len(t, rules, 1, "the missing socket gets no rule")
	assert.Contains(t, fmt.Sprint(rules[0]), socket)
	assert.Equal(t, uint64(llsyscall.AccessFSResolveUnix), landlockAdjustAccessForPath(socket, uint64(llsyscall.AccessFSResolveUnix)))

	cfg := landlockSelectConfig(policy)
	assert.NotZero(t, uint64(cfg.HandledAccessFS)&uint64(llsyscall.AccessFSResolveUnix))
}
