package shim

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func useSystemPaths(t *testing.T, dir string) {
	t.Helper()
	systemBinDirOverride = filepath.Join(dir, "bin")
	systemProfilePathOverride = filepath.Join(dir, "profile.d", "pmg.sh")
	t.Cleanup(func() {
		systemBinDirOverride = ""
		systemProfilePathOverride = ""
	})
}

func TestSystemShimManagerInstallAndRemove(t *testing.T) {
	root := t.TempDir()
	useSystemPaths(t, root)

	mgr, err := NewSystemShimManager()
	require.NoError(t, err)
	assert.True(t, mgr.config.SkipShellRc)
	assert.True(t, mgr.config.ManageProfile)
	assert.Equal(t, SystemBinDir(), mgr.GetBinDir())

	require.NoError(t, mgr.Install())
	assert.True(t, SystemShimsInstalled())
	assert.True(t, SystemProfileInstalled())

	npmShim := filepath.Join(SystemBinDir(), "npm")
	content, err := os.ReadFile(npmShim)
	require.NoError(t, err)
	assert.Contains(t, string(content), "export PMG_SHIM_PATH")
	assert.Contains(t, string(content), "pmg setup install")
	assert.Contains(t, string(content), "pmg setup remove")

	profile, err := os.ReadFile(SystemProfilePath())
	require.NoError(t, err)
	assert.Contains(t, string(profile), mgr.GetBinDir())
	assert.Contains(t, string(profile), systemProfileMarker)

	require.NoError(t, mgr.Install())
	profile2, err := os.ReadFile(SystemProfilePath())
	require.NoError(t, err)
	assert.Equal(t, string(profile), string(profile2))

	require.NoError(t, mgr.Remove())
	assert.False(t, SystemShimsInstalled())
	assert.False(t, SystemProfileInstalled())
	require.NoError(t, mgr.Remove())
}

func TestSystemShimManagerDoesNotTouchUserRc(t *testing.T) {
	root := t.TempDir()
	useSystemPaths(t, root)

	home := t.TempDir()
	bashrc := filepath.Join(home, ".bashrc")
	require.NoError(t, os.WriteFile(bashrc, []byte("# user bashrc\n"), 0o644))

	mgr, err := NewSystemShimManager()
	require.NoError(t, err)
	mgr.config.HomeDir = home
	require.NoError(t, mgr.Install())

	content, err := os.ReadFile(bashrc)
	require.NoError(t, err)
	assert.Equal(t, "# user bashrc\n", string(content))
}

func TestSystemShimsInstalledIgnoresUnmanagedFiles(t *testing.T) {
	root := t.TempDir()
	useSystemPaths(t, root)
	require.NoError(t, os.MkdirAll(SystemBinDir(), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(SystemBinDir(), "README"), []byte("not a shim"), 0o644))

	assert.False(t, SystemShimsInstalled())

	require.NoError(t, os.WriteFile(
		filepath.Join(SystemBinDir(), "npm"),
		[]byte("#!/bin/sh\n# PMG shim - do not edit, managed by pmg setup\n"),
		0o755,
	))
	assert.True(t, SystemShimsInstalled())
}

func TestWriteSystemProfileRepairsStalePath(t *testing.T) {
	root := t.TempDir()
	useSystemPaths(t, root)
	require.NoError(t, os.MkdirAll(filepath.Dir(SystemProfilePath()), 0o755))
	require.NoError(t, os.WriteFile(
		SystemProfilePath(),
		[]byte("# PMG system shims\nexport PATH=\"/stale/path:$PATH\"\n"),
		0o644,
	))

	require.NoError(t, writeSystemProfile())

	content, err := os.ReadFile(SystemProfilePath())
	require.NoError(t, err)
	assert.Contains(t, string(content), SystemBinDir())
	assert.NotContains(t, string(content), "/stale/path")
}

func TestValidateSystemExecutableRejectsPrivateBinary(t *testing.T) {
	privateDir := t.TempDir()
	privateExecutable := filepath.Join(privateDir, "pmg")
	require.NoError(t, os.WriteFile(privateExecutable, []byte("binary"), 0o700))

	err := validateSystemExecutable(privateExecutable)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not executable by all users")
}
