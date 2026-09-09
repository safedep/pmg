//go:build windows

package shim

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"
)

func TestLookInDirs(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(second, "npm.cmd"), nil, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(second, "pip.exe"), nil, 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(first, "uv.exe"), 0o755))
	exts := []string{".COM", ".EXE", ".BAT", ".CMD"}

	t.Run("applies PATHEXT in order across directories and lower-cases the extension", func(t *testing.T) {
		got, err := lookInDirs("npm", []string{first, second}, exts)
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(second, "npm.cmd"), got)

		got, err = lookInDirs("pip", []string{first, second}, exts)
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(second, "pip.exe"), got)
	})

	t.Run("skips a directory that carries the name", func(t *testing.T) {
		_, err := lookInDirs("uv", []string{first, second}, exts)
		assert.ErrorIs(t, err, exec.ErrNotFound)
	})

	t.Run("reports a missing name like LookPath", func(t *testing.T) {
		_, err := lookInDirs("yarn", []string{first, second}, exts)
		var execErr *exec.Error
		require.ErrorAs(t, err, &execErr)
		assert.Equal(t, "yarn", execErr.Name)
	})
}

// setMachinePath writes value as the machine PATH in the scratch key that
// isolateMachinePath armed.
func setMachinePath(t *testing.T, value string) {
	t.Helper()
	key, err := registry.OpenKey(machineEnvironmentRoot, machineEnvironmentKey, registry.SET_VALUE)
	require.NoError(t, err)
	defer key.Close()
	require.NoError(t, key.SetExpandStringValue(pathValueName, value))
}

// A manager on the machine PATH resolves before the same name on the user
// PATH, because Windows builds a process PATH in that order.
func TestInspectInterceptionMachinePathFirst(t *testing.T) {
	isolateUserPath(t)
	isolateMachinePath(t)

	machineDir, shimDir := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(machineDir, "npm.cmd"), nil, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(shimDir, "npm.cmd"), nil, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(shimDir, "pnpm.cmd"), nil, 0o644))

	setMachinePath(t, machineDir)
	require.NoError(t, writeUserPath([]string{shimDir}, true))

	inspection, err := InspectInterception([]string{"npm", "pnpm", "yarn"}, []string{shimDir})
	require.NoError(t, err)

	assert.Equal(t, []string{machineDir, shimDir}, inspection.PathEntries)
	assert.Equal(t, []ManagerResolution{
		{Name: "npm", Path: filepath.Join(machineDir, "npm.cmd")},
		{Name: "pnpm", Path: filepath.Join(shimDir, "pnpm.cmd"), UnderShim: true},
	}, inspection.Resolutions)
}
