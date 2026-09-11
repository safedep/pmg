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
	// One flat key per test, so deleting it leaves no parent behind.
	keyPath := `Software\pmg-test-` + strings.ReplaceAll(t.Name(), "/", "_")
	key, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	require.NoError(t, err)
	require.NoError(t, key.Close())

	orig := userPath.key
	userPath.key = keyPath
	t.Cleanup(func() {
		userPath.key = orig
		require.NoError(t, registry.DeleteKey(registry.CURRENT_USER, keyPath))
	})
}

func TestShimManagerInstallWritesCmdShims(t *testing.T) {
	isolateUserPath(t)
	homeDir := t.TempDir()
	binDir := filepath.Join(homeDir, "safedep", "pmg", "bin")
	// A percent sign in the binary path must not start a batch expansion. A
	// closing parenthesis must not end the if block, and an ampersand must
	// not start a second command.
	pmgBin := filepath.Join(homeDir, "100% (x86) & co", "pmg.exe")

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
		assert.Contains(t, body, "set PMG_RAW_ARGS=%*\r\n")
		assert.Contains(t, body, fmt.Sprintf(`"%s" %s %%*`+"\r\n", strings.ReplaceAll(pmgBin, "%", "%%"), pm))
		assert.Contains(t, body, fmt.Sprintf(`if not exist "%s" (`+"\r\n", strings.ReplaceAll(pmgBin, "%", "%%")))
		assert.Contains(t, body, fmt.Sprintf(`PMG binary not found: "%s" 1>&2`+"\r\n", strings.ReplaceAll(pmgBin, "%", "%%")))
		assert.Contains(t, body, `or delete "%~dp0" to remove the shims 1>&2`+"\r\n")
		assert.Contains(t, body, "  exit /b 127\r\n")
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
		require.NoError(t, userPath.write([]string{`%USERPROFILE%\bin`, `C:\Tools`}, true))

		require.NoError(t, userPath.prepend(shimDir))
		require.NoError(t, userPath.prepend(shimDir))

		entries, expand, err := userPath.read()
		require.NoError(t, err)
		assert.Equal(t, []string{shimDir, `%USERPROFILE%\bin`, `C:\Tools`}, entries)
		assert.True(t, expand)
	})

	t.Run("contains folds case", func(t *testing.T) {
		found, err := userPath.contains(strings.ToUpper(shimDir))
		require.NoError(t, err)
		assert.True(t, found)
	})

	t.Run("removes only the shim entry", func(t *testing.T) {
		require.NoError(t, userPath.remove(strings.ToLower(shimDir)))

		entries, _, err := userPath.read()
		require.NoError(t, err)
		assert.Equal(t, []string{`%USERPROFILE%\bin`, `C:\Tools`}, entries)

		found, err := userPath.contains(shimDir)
		require.NoError(t, err)
		assert.False(t, found)
	})

	t.Run("a missing Path value reads as empty", func(t *testing.T) {
		key, err := registry.OpenKey(registry.CURRENT_USER, userPath.key, registry.SET_VALUE)
		require.NoError(t, err)
		require.NoError(t, key.DeleteValue(pathValueName))
		require.NoError(t, key.Close())

		entries, _, err := userPath.read()
		require.NoError(t, err)
		assert.Empty(t, entries)

		require.NoError(t, userPath.prepend(shimDir))
		found, err := userPath.contains(shimDir)
		require.NoError(t, err)
		assert.True(t, found)
	})

	t.Run("removing the only entry leaves no value behind", func(t *testing.T) {
		require.NoError(t, userPath.remove(shimDir))

		key, err := registry.OpenKey(registry.CURRENT_USER, userPath.key, registry.QUERY_VALUE)
		require.NoError(t, err)
		defer key.Close()
		_, _, err = key.GetStringValue(pathValueName)
		assert.ErrorIs(t, err, registry.ErrNotExist)
	})
}

// isolateMachinePath points the machine PATH code at a scratch key under
// HKCU. HKLM needs elevation, and the code does not care which root it
// opens.
func isolateMachinePath(t *testing.T) {
	t.Helper()
	keyPath := `Software\pmg-test-machine-` + strings.ReplaceAll(t.Name(), "/", "_")
	key, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	require.NoError(t, err)
	require.NoError(t, key.Close())

	orig := machinePath
	machinePath.root, machinePath.key = registry.CURRENT_USER, keyPath
	t.Cleanup(func() {
		machinePath = orig
		require.NoError(t, registry.DeleteKey(registry.CURRENT_USER, keyPath))
	})
}

// Windows builds a new process's PATH as the machine value, then the user
// value. A manager installed for the machine therefore sits ahead of a user
// PATH entry, and the doctor must see that order.
func TestRegistryPathHalves(t *testing.T) {
	isolateUserPath(t)
	isolateMachinePath(t)
	setRegistryPath(t, machinePath, `C:\Program Files\nodejs;%SystemRoot%\System32`)
	require.NoError(t, userPath.write([]string{`%LOCALAPPDATA%\safedep\pmg\bin`, `"C:\Quoted Tools"`}, true))

	machine, user, err := registryPathHalves()
	require.NoError(t, err)

	assert.Equal(t, []string{
		`C:\Program Files\nodejs`,
		filepath.Join(os.Getenv("SystemRoot"), "System32"),
	}, machine, "%VAR% expands from this process's environment")
	assert.Equal(t, []string{
		filepath.Join(os.Getenv("LOCALAPPDATA"), `safedep\pmg\bin`),
		`C:\Quoted Tools`,
	}, user, "SplitList strips the quotes a PATH entry may carry")
}

// prepend moves the shim directory to the front when an installer prepended
// its own directory after the last `pmg setup install`.
func TestPrependMovesTheShimDirectoryToTheFront(t *testing.T) {
	isolateUserPath(t)
	shimDir := `C:\Users\dev\AppData\Local\safedep\pmg\bin`
	pythonDir := `C:\Users\dev\AppData\Local\Programs\Python\Python312\Scripts`

	require.NoError(t, userPath.write([]string{pythonDir, shimDir, `C:\Tools`}, true))
	require.NoError(t, userPath.prepend(shimDir))

	entries, _, err := userPath.read()
	require.NoError(t, err)
	assert.Equal(t, []string{shimDir, pythonDir, `C:\Tools`}, entries)

	// Already first, so a second run writes nothing new.
	require.NoError(t, userPath.prepend(shimDir))
	entries, _, err = userPath.read()
	require.NoError(t, err)
	assert.Equal(t, []string{shimDir, pythonDir, `C:\Tools`}, entries)
}
