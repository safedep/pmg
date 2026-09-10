//go:build windows

package shim

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"
)

func TestLookPathIn(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(second, "npm.cmd"), nil, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(second, "pip.exe"), nil, 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(first, "uv.exe"), 0o755))
	t.Setenv("PATHEXT", ".COM;.EXE;.BAT;.CMD")

	t.Run("applies PATHEXT in order and lower-cases the extension", func(t *testing.T) {
		got, err := lookPathIn("npm", []string{first, second})
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(second, "npm.cmd"), got)

		got, err = lookPathIn("pip", []string{first, second})
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(second, "pip.exe"), got)
	})

	t.Run("skips a directory that carries the name", func(t *testing.T) {
		_, err := lookPathIn("uv", []string{first, second})
		assert.ErrorIs(t, err, exec.ErrNotFound)
	})

	t.Run("reports a missing name like LookPath", func(t *testing.T) {
		_, err := lookPathIn("yarn", []string{first, second})
		var execErr *exec.Error
		require.ErrorAs(t, err, &execErr)
		assert.Equal(t, "yarn", execErr.Name)
	})
}

// A trailing semicolon in PATHEXT would leave an empty extension, which
// matches a file with no extension. npm ships an sh script called `npm` next
// to npm.cmd, and cmd.exe cannot run it.
func TestPathExtensionsDropsAnEmptyEntry(t *testing.T) {
	t.Setenv("PATHEXT", ".EXE;.CMD;")
	assert.Equal(t, []string{".EXE", ".CMD"}, pathExtensions())

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "npm"), nil, 0o644))
	_, err := lookPathIn("npm", []string{dir})
	assert.ErrorIs(t, err, exec.ErrNotFound)
}

// setRegistryPath writes value as the PATH of one scratch key.
func setRegistryPath(t *testing.T, root registry.Key, keyPath, value string) {
	t.Helper()
	key, err := registry.OpenKey(root, keyPath, registry.SET_VALUE)
	require.NoError(t, err)
	defer key.Close()
	require.NoError(t, key.SetExpandStringValue(pathValueName, value))
}

// Every case here writes both registry halves and the process PATH, so the
// runner's own PATH cannot reach the result.
func TestInspectInterception(t *testing.T) {
	newManagerDir := func(t *testing.T, names ...string) string {
		t.Helper()
		dir := t.TempDir()
		for _, name := range names {
			require.NoError(t, os.WriteFile(filepath.Join(dir, name+".cmd"), nil, 0o644))
		}
		return dir
	}
	joinPath := func(dirs ...string) string { return strings.Join(dirs, ";") }

	// Windows builds a process PATH as the machine value, then the user
	// value, so a manager a machine-wide installer put on PATH resolves
	// before a user-scope shim. Its origin decides the remedy.
	t.Run("machine PATH resolves before the user PATH", func(t *testing.T) {
		isolateUserPath(t)
		isolateMachinePath(t)
		machineDir := newManagerDir(t, "npm")
		shimDir := newManagerDir(t, "npm", "pnpm")

		setRegistryPath(t, machineEnvironmentRoot, machineEnvironmentKey, machineDir)
		require.NoError(t, writeUserPath([]string{shimDir}, true))
		t.Setenv("PATH", joinPath(machineDir, shimDir))

		inspection, err := InspectInterception([]string{"npm", "pnpm", "yarn"}, []string{shimDir})
		require.NoError(t, err)

		assert.Equal(t, []string{machineDir, shimDir}, inspection.PathEntries)
		assert.Equal(t, []ManagerResolution{
			{Name: "npm", Path: filepath.Join(machineDir, "npm.cmd"), Origin: OriginMachine},
			{Name: "pnpm", Path: filepath.Join(shimDir, "pnpm.cmd"), UnderShim: true, Origin: OriginUser},
		}, inspection.Resolutions)
	})

	// The user half is the one PMG can reorder, so a manager shadowed from
	// there gets a different remedy.
	t.Run("a user PATH entry ahead of the shims", func(t *testing.T) {
		isolateUserPath(t)
		isolateMachinePath(t)
		pythonDir := newManagerDir(t, "pip")
		shimDir := newManagerDir(t, "pip")

		setRegistryPath(t, machineEnvironmentRoot, machineEnvironmentKey, `C:\Windows\System32`)
		require.NoError(t, writeUserPath([]string{pythonDir, shimDir}, true))
		t.Setenv("PATH", joinPath(`C:\Windows\System32`, pythonDir, shimDir))

		inspection, err := InspectInterception([]string{"pip"}, []string{shimDir})
		require.NoError(t, err)

		assert.Equal(t, []ManagerResolution{
			{Name: "pip", Path: filepath.Join(pythonDir, "pip.cmd"), Origin: OriginUser},
		}, inspection.Resolutions)
	})

	// `fnm env | Invoke-Expression` in $PROFILE prepends a directory that
	// holds npm. The registry never sees it, so reading the registry alone
	// would report the shims as winning in a shell where they do not.
	t.Run("a shell profile ahead of the shims", func(t *testing.T) {
		isolateUserPath(t)
		isolateMachinePath(t)
		profileDir := newManagerDir(t, "npm")
		shimDir := newManagerDir(t, "npm")

		setRegistryPath(t, machineEnvironmentRoot, machineEnvironmentKey, `C:\Windows\System32`)
		require.NoError(t, writeUserPath([]string{shimDir}, true))
		t.Setenv("PATH", joinPath(profileDir, `C:\Windows\System32`, shimDir))

		inspection, err := InspectInterception([]string{"npm"}, []string{shimDir})
		require.NoError(t, err)

		assert.Equal(t, []ManagerResolution{
			{Name: "npm", Path: filepath.Join(profileDir, "npm.cmd"), Origin: OriginProfile},
		}, inspection.Resolutions)
	})

	// Doctor often runs in the shell that ran `pmg setup install`, whose
	// process PATH predates the registry write. The registry answer stands,
	// because every directory that shell resolves from is in the registry.
	t.Run("a stale shell keeps the registry answer", func(t *testing.T) {
		isolateUserPath(t)
		isolateMachinePath(t)
		nodeDir := newManagerDir(t, "npm")
		shimDir := newManagerDir(t, "npm")

		setRegistryPath(t, machineEnvironmentRoot, machineEnvironmentKey, nodeDir)
		require.NoError(t, writeUserPath([]string{shimDir}, true))
		// The shell started before the install, so it has no shim directory.
		t.Setenv("PATH", nodeDir)

		inspection, err := InspectInterception([]string{"npm"}, []string{shimDir})
		require.NoError(t, err)

		assert.Equal(t, []ManagerResolution{
			{Name: "npm", Path: filepath.Join(nodeDir, "npm.cmd"), Origin: OriginMachine},
		}, inspection.Resolutions)
	})
}
