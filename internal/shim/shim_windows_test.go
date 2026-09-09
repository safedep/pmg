//go:build windows

package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"
)

// isolateUserPath points the user PATH code at a throwaway registry key, so
// a test never edits the real HKCU\Environment.
func isolateUserPath(t *testing.T) {
	t.Helper()
	keyPath := fmt.Sprintf(`Software\safedep\pmg-test\%s`, strings.ReplaceAll(t.Name(), "/", "_"))
	key, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	require.NoError(t, err)
	require.NoError(t, key.Close())

	orig := userEnvironmentKey
	userEnvironmentKey = keyPath
	t.Cleanup(func() {
		userEnvironmentKey = orig
		require.NoError(t, registry.DeleteKey(registry.CURRENT_USER, keyPath))
	})
}

func TestShimManagerInstallWritesCmdShims(t *testing.T) {
	isolateUserPath(t)
	homeDir := t.TempDir()
	binDir := filepath.Join(homeDir, "safedep", "pmg", "bin")
	// A percent sign in the binary path must not start a batch expansion.
	pmgBin := filepath.Join(homeDir, "100%", "pmg.exe")

	mgr := NewShimManager(ShimConfig{
		BinDir:          binDir,
		HomeDir:         homeDir,
		PMGBin:          pmgBin,
		PackageManagers: []string{"npm", "pip"},
	})
	require.NoError(t, mgr.Install())

	for _, pm := range []string{"npm", "pip"} {
		content, err := os.ReadFile(filepath.Join(binDir, pm+".cmd"))
		require.NoError(t, err, "shim %s.cmd should exist", pm)
		body := string(content)

		assert.True(t, strings.HasPrefix(body, "@echo off\r\n"))
		assert.Contains(t, body, "rem "+shimScriptMarker+"\r\n")
		assert.Contains(t, body, "setlocal DisableDelayedExpansion\r\n")
		assert.Contains(t, body, `set "PMG_SHIM_PATH=%~f0"`+"\r\n")
		assert.Contains(t, body, `set "PMG_RAW_ARGS=%*"`+"\r\n")
		assert.Contains(t, body, fmt.Sprintf(`"%s" %s %%*`+"\r\n", strings.ReplaceAll(pmgBin, "%", "%%"), pm))
		assert.True(t, strings.HasSuffix(body, "exit /b %ERRORLEVEL%\r\n"))
	}

	assert.True(t, shimsPresent(binDir), "shimsPresent must recognise a .cmd shim")

	installed, err := mgr.IsInstalled()
	require.NoError(t, err)
	assert.True(t, installed)
}

func TestShimManagerRemoveDeletesShimsAndPathEntry(t *testing.T) {
	isolateUserPath(t)
	homeDir := t.TempDir()
	binDir := filepath.Join(homeDir, "safedep", "pmg", "bin")

	mgr := NewShimManager(ShimConfig{
		BinDir:          binDir,
		HomeDir:         homeDir,
		PMGBin:          filepath.Join(homeDir, "pmg.exe"),
		PackageManagers: []string{"npm"},
	})
	require.NoError(t, mgr.Install())
	require.NoError(t, mgr.Remove())

	assert.NoDirExists(t, binDir)
	installed, err := mgr.IsInstalled()
	require.NoError(t, err)
	assert.False(t, installed)
}

func TestUserPathRegistry(t *testing.T) {
	isolateUserPath(t)
	shimDir := `C:\Users\dev\AppData\Local\safedep\pmg\bin`

	t.Run("prepends once and keeps the value type", func(t *testing.T) {
		// Windows writes the default user PATH as REG_EXPAND_SZ so
		// %USERPROFILE% style entries stay unexpanded.
		require.NoError(t, writeUserPath([]string{`%USERPROFILE%\bin`, `C:\Tools`}, true))

		require.NoError(t, registerUserPath(shimDir))
		require.NoError(t, registerUserPath(shimDir))

		entries, expand, err := readUserPath()
		require.NoError(t, err)
		assert.Equal(t, []string{shimDir, `%USERPROFILE%\bin`, `C:\Tools`}, entries)
		assert.True(t, expand)
	})

	t.Run("contains folds case", func(t *testing.T) {
		found, err := userPathContains(strings.ToUpper(shimDir))
		require.NoError(t, err)
		assert.True(t, found)
	})

	t.Run("removes only the shim entry", func(t *testing.T) {
		require.NoError(t, unregisterUserPath(strings.ToLower(shimDir)))

		entries, _, err := readUserPath()
		require.NoError(t, err)
		assert.Equal(t, []string{`%USERPROFILE%\bin`, `C:\Tools`}, entries)

		found, err := userPathContains(shimDir)
		require.NoError(t, err)
		assert.False(t, found)
	})

	t.Run("a missing Path value reads as empty", func(t *testing.T) {
		key, err := registry.OpenKey(registry.CURRENT_USER, userEnvironmentKey, registry.SET_VALUE)
		require.NoError(t, err)
		require.NoError(t, key.DeleteValue(pathValueName))
		require.NoError(t, key.Close())

		entries, _, err := readUserPath()
		require.NoError(t, err)
		assert.Empty(t, entries)

		require.NoError(t, registerUserPath(shimDir))
		found, err := userPathContains(shimDir)
		require.NoError(t, err)
		assert.True(t, found)
	})
}
