//go:build windows

package shim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safedep/pmg/internal/fsutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// Two real paths pin validateSystemExecutable to the operating system.
// cmd.exe is what a system binary must look like. A file in the temp
// directory is what a user-scope install looks like.
func TestValidateSystemExecutableOnRealFiles(t *testing.T) {
	cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	assert.NoError(t, validateSystemExecutable(cmdExe))

	userFile := filepath.Join(t.TempDir(), "pmg.exe")
	require.NoError(t, os.WriteFile(userFile, []byte("binary"), 0o755))
	err := validateSystemExecutable(userFile)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "failed to", "the file was read, and rejected on its rights")
}

func TestMachinePathRegistry(t *testing.T) {
	isolateMachinePath(t)
	shimDir := `C:\Program Files\safedep\pmg\bin`

	t.Run("registers first and keeps the value type", func(t *testing.T) {
		setRegistryPath(t, machineEnvironmentRoot, machineEnvironmentKey,
			`%SystemRoot%\system32;C:\Program Files\nodejs\`)

		require.NoError(t, registerMachinePath(shimDir))
		require.NoError(t, registerMachinePath(shimDir))

		entries, expand, err := readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
		require.NoError(t, err)
		assert.Equal(t, []string{shimDir, `%SystemRoot%\system32`, `C:\Program Files\nodejs\`}, entries)
		assert.True(t, expand)
	})

	t.Run("moves the directory back to the front", func(t *testing.T) {
		require.NoError(t, writeRawPath(machineEnvironmentRoot, machineEnvironmentKey,
			[]string{`C:\Program Files\nodejs\`, shimDir + `\`}, true))

		require.NoError(t, registerMachinePath(shimDir))

		entries, _, err := readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
		require.NoError(t, err)
		assert.Equal(t, []string{shimDir, `C:\Program Files\nodejs\`}, entries)
	})

	t.Run("an entry written through a variable counts as present", func(t *testing.T) {
		require.NoError(t, writeRawPath(machineEnvironmentRoot, machineEnvironmentKey,
			[]string{`%ProgramFiles%\safedep\pmg\bin`, `C:\Tools`}, true))

		found, err := machinePathContains(filepath.Join(os.Getenv("ProgramFiles"), `safedep\pmg\bin`))
		require.NoError(t, err)
		assert.True(t, found)
	})

	t.Run("append adds once at the end and moves nothing", func(t *testing.T) {
		require.NoError(t, writeRawPath(machineEnvironmentRoot, machineEnvironmentKey,
			[]string{shimDir, `C:\Tools`}, true))

		require.NoError(t, appendMachinePath(`C:\Program Files\safedep\pmg`))
		require.NoError(t, appendMachinePath(`C:\Program Files\safedep\pmg`))
		require.NoError(t, appendMachinePath(`c:\tools`))

		entries, _, err := readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
		require.NoError(t, err)
		assert.Equal(t, []string{shimDir, `C:\Tools`, `C:\Program Files\safedep\pmg`}, entries)
	})

	t.Run("unregister removes only the directory and never the value", func(t *testing.T) {
		require.NoError(t, writeRawPath(machineEnvironmentRoot, machineEnvironmentKey,
			[]string{shimDir, `C:\Tools`}, false))

		require.NoError(t, unregisterMachinePath(strings.ToLower(shimDir)))
		require.NoError(t, unregisterMachinePath(shimDir))

		entries, expand, err := readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
		require.NoError(t, err)
		assert.Equal(t, []string{`C:\Tools`}, entries)
		assert.False(t, expand, "a REG_SZ value stays REG_SZ")

		require.NoError(t, unregisterMachinePath(`C:\Tools`))
		entries, _, err = readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
		require.NoError(t, err)
		assert.Empty(t, entries)
	})
}

// useSystemPaths is the Windows twin of the Unix helper. The temp directory
// is user-owned, so the ACL checks are off and covered by their own tests.
func useSystemPaths(t *testing.T, dir string) {
	t.Helper()
	isolateMachinePath(t)
	systemBinDirOverride = filepath.Join(dir, "bin")
	systemExecutableOwnershipCheck = false

	exe := filepath.Join(dir, "pmg.exe")
	require.NoError(t, os.WriteFile(exe, []byte("binary"), 0o755))
	resolveExecutable = func() (string, error) { return exe, nil }

	t.Cleanup(func() {
		systemBinDirOverride = ""
		systemExecutableOwnershipCheck = true
		resolveExecutable = currentExecutable
	})
}

func TestSystemShimManagerInstallAndRemove(t *testing.T) {
	root := t.TempDir()
	useSystemPaths(t, root)
	setRegistryPath(t, machineEnvironmentRoot, machineEnvironmentKey, `C:\Program Files\nodejs\`)

	mgr, err := NewSystemShimManager()
	require.NoError(t, err)
	assert.True(t, mgr.config.SkipUserPath)
	assert.True(t, mgr.config.SystemProfile)
	assert.Equal(t, "", SystemProfilePath())

	require.NoError(t, mgr.Install())
	assert.True(t, SystemShimsInstalled())
	assert.True(t, SystemPathInstalled())

	entries, _, err := readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
	require.NoError(t, err)
	assert.Equal(t, []string{SystemBinDir(), `C:\Program Files\nodejs\`, root}, entries,
		"the shim directory goes first and the binary's directory last, so `pmg` itself resolves")

	content, err := os.ReadFile(filepath.Join(SystemBinDir(), "npm.cmd"))
	require.NoError(t, err)
	assert.Contains(t, string(content), filepath.Join(root, "pmg.exe"))

	bin, ok := SystemShimBinary()
	require.True(t, ok)
	assert.Equal(t, filepath.Join(root, "pmg.exe"), bin)

	// A second install is a no-op on the PATH and rewrites the shims.
	require.NoError(t, mgr.Install())
	entries, _, err = readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
	require.NoError(t, err)
	assert.Equal(t, []string{SystemBinDir(), `C:\Program Files\nodejs\`, root}, entries)

	require.NoError(t, mgr.Remove())
	assert.False(t, SystemShimsInstalled())
	assert.False(t, SystemPathInstalled())
	require.NoError(t, mgr.Remove())

	entries, _, err = readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
	require.NoError(t, err)
	assert.Equal(t, []string{`C:\Program Files\nodejs\`, root}, entries, "the binary stays, so its directory stays on PATH")
}

// An elevated install writes administrator-only shims. This is the path a
// real install takes.
func TestSystemShimManagerInstallForcesAdminOnlyShims(t *testing.T) {
	if !fsutil.ProcessIsElevated() {
		t.Skip("needs an elevated process")
	}
	root := t.TempDir()
	useSystemPaths(t, root)
	setRegistryPath(t, machineEnvironmentRoot, machineEnvironmentKey, `C:\Tools`)

	mgr, err := NewSystemShimManager()
	require.NoError(t, err)
	require.NoError(t, mgr.Install())

	// Not validateSystemShimDir: its ancestor walk reaches the user's
	// profile, which they own. The directory and every shim are checked.
	assert.NoError(t, fsutil.RequireAdminOnlyWritable(SystemBinDir()))
	entries, err := os.ReadDir(SystemBinDir())
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	for _, entry := range entries {
		assert.NoError(t, fsutil.RequireAdminOnlyWritable(filepath.Join(SystemBinDir(), entry.Name())), entry.Name())
	}
}

func TestDefaultSystemBinDirUnderProgramFiles(t *testing.T) {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(programFiles, `safedep\pmg\bin`), defaultSystemBinDir())

	// The environment does not steer it. A caller's shell controls the
	// environment, and a directory of their choosing must not become the
	// first entry of the machine PATH.
	t.Setenv("ProgramFiles", `C:\Users\dev\evil`)
	assert.Equal(t, filepath.Join(programFiles, `safedep\pmg\bin`), defaultSystemBinDir())
}
