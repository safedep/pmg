//go:build unix

package shim

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShimScriptsExecutableUnderRestrictiveUmask(t *testing.T) {
	root := t.TempDir()
	useSystemPaths(t, root)

	oldUmask := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(oldUmask) })

	mgr, err := NewSystemShimManager()
	require.NoError(t, err)
	require.NoError(t, mgr.Install())

	info, err := os.Stat(filepath.Join(mgr.GetBinDir(), "npm"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), info.Mode().Perm(),
		"shims must stay world-executable regardless of the installer's umask")
}
