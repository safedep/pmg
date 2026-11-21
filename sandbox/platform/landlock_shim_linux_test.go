//go:build linux

package platform

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestShimFilesystemRulesSkipUnopenablePaths(t *testing.T) {
	worktree := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: /elsewhere\n"), 0o644))

	rules, closeRules := shimFilesystemRules([]landlockPathRule{
		{Path: worktree, Access: landlockReadAccess},
		{Path: filepath.Join(worktree, ".git", "config"), Access: landlockReadAccess},
		{Path: filepath.Join(worktree, "missing"), Access: landlockReadAccess},
	})
	t.Cleanup(closeRules)

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
	subdir := filepath.Join(dir, "run")
	require.NoError(t, os.Mkdir(subdir, 0o700))

	policy := &landlockExecPolicy{FilesystemRules: []landlockPathRule{
		{Path: socket, Access: uint64(llsyscall.AccessFSResolveUnix)},
		{Path: missing, Access: uint64(llsyscall.AccessFSResolveUnix)},
		{Path: subdir, Access: uint64(llsyscall.AccessFSResolveUnix)},
	}}

	rules, closeRules := shimFilesystemRules(policy.FilesystemRules)
	t.Cleanup(closeRules)
	require.Len(t, rules, 1, "a missing socket and a directory get no rule, because a directory rule opens every socket below it")

	// The rule names the descriptor that the check saw. A later swap of the
	// path for a directory does not change what the rule grants.
	var fdPath string
	_, err = fmt.Sscanf(fmt.Sprint(rules[0]), "REQUIRE {resolve_unix} for paths [%s", &fdPath)
	require.NoError(t, err, "rule: %v", rules[0])
	fdPath = strings.TrimSuffix(fdPath, "]")
	require.NoError(t, os.Remove(socket))
	require.NoError(t, os.Mkdir(socket, 0o700))
	var st unix.Stat_t
	require.NoError(t, unix.Stat(fdPath, &st))
	assert.Equal(t, uint32(unix.S_IFSOCK), st.Mode&unix.S_IFMT)
	assert.Equal(t, uint64(llsyscall.AccessFSResolveUnix), landlockAdjustAccessForPath(socket, uint64(llsyscall.AccessFSResolveUnix)))

	cfg := landlockSelectConfig(policy)
	assert.NotZero(t, uint64(cfg.HandledAccessFS)&uint64(llsyscall.AccessFSResolveUnix))
}
