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
// a test never edits the real HKCU\Environment. It isolates the machine PATH
// too, because an elevated install writes there and the CI runner is
// elevated.
func isolateUserPath(t *testing.T) {
	t.Helper()
	// One flat key per test, so deleting it leaves no parent behind.
	keyPath := `Software\pmg-test-` + strings.ReplaceAll(t.Name(), "/", "_")
	key, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	require.NoError(t, err)
	require.NoError(t, key.Close())

	orig := userEnvironmentKey
	userEnvironmentKey = keyPath
	t.Cleanup(func() {
		userEnvironmentKey = orig
		require.NoError(t, registry.DeleteKey(registry.CURRENT_USER, keyPath))
	})
	isolateMachinePath(t)
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

	t.Run("removing the only entry leaves no value behind", func(t *testing.T) {
		require.NoError(t, unregisterUserPath(shimDir))

		key, err := registry.OpenKey(registry.CURRENT_USER, userEnvironmentKey, registry.QUERY_VALUE)
		require.NoError(t, err)
		defer key.Close()
		_, _, err = key.GetStringValue(pathValueName)
		assert.ErrorIs(t, err, registry.ErrNotExist)
	})
}

// isolateMachinePath points the machine PATH reader at a scratch key under
// HKCU. HKLM needs elevation, and the reader does not care which root it
// opens.
func isolateMachinePath(t *testing.T) {
	t.Helper()
	keyPath := `Software\pmg-test-machine-` + strings.ReplaceAll(t.Name(), "/", "_")
	key, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	require.NoError(t, err)
	require.NoError(t, key.Close())

	origRoot, origKey := machineEnvironmentRoot, machineEnvironmentKey
	machineEnvironmentRoot, machineEnvironmentKey = registry.CURRENT_USER, keyPath
	t.Cleanup(func() {
		machineEnvironmentRoot, machineEnvironmentKey = origRoot, origKey
		require.NoError(t, registry.DeleteKey(registry.CURRENT_USER, keyPath))
	})
}

// Windows builds a new process's PATH as the machine value, then the user
// value. A manager installed for the machine therefore sits ahead of a user
// PATH entry, and the doctor must see that order.
func TestRegistryPathHalves(t *testing.T) {
	isolateUserPath(t)
	isolateMachinePath(t)
	setRegistryPath(t, machineEnvironmentRoot, machineEnvironmentKey,
		`C:\Program Files\nodejs;%SystemRoot%\System32`)
	require.NoError(t, writeUserPath([]string{`%LOCALAPPDATA%\safedep\pmg\bin`, `"C:\Quoted Tools"`}, true))

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

// registerUserPath moves the shim directory to the front when an installer
// prepended its own directory after the last `pmg setup install`.
func TestRegisterUserPathMovesTheShimDirectoryToTheFront(t *testing.T) {
	isolateUserPath(t)
	shimDir := `C:\Users\dev\AppData\Local\safedep\pmg\bin`
	pythonDir := `C:\Users\dev\AppData\Local\Programs\Python\Python312\Scripts`

	require.NoError(t, writeUserPath([]string{pythonDir, shimDir, `C:\Tools`}, true))
	require.NoError(t, registerUserPath(shimDir))

	entries, _, err := readUserPath()
	require.NoError(t, err)
	assert.Equal(t, []string{shimDir, pythonDir, `C:\Tools`}, entries)

	// Already first, so a second run writes nothing new.
	require.NoError(t, registerUserPath(shimDir))
	entries, _, err = readUserPath()
	require.NoError(t, err)
	assert.Equal(t, []string{shimDir, pythonDir, `C:\Tools`}, entries)
}

// The machine PATH form of the shim directory names the per-user variable,
// so one machine entry expands to each user's own directory.
func TestMachinePathEntry(t *testing.T) {
	t.Setenv("LOCALAPPDATA", `C:\Users\dev\AppData\Local`)
	t.Setenv("USERPROFILE", `C:\Users\dev`)

	tests := []struct {
		name, binDir, want string
	}{
		{"data directory", `C:\Users\dev\AppData\Local\safedep\pmg\bin`, `%LOCALAPPDATA%\safedep\pmg\bin`},
		{"legacy home directory", `C:\Users\dev\.pmg\bin`, `%USERPROFILE%\.pmg\bin`},
		{"case of the prefix does not matter", `c:\users\DEV\appdata\local\safedep\pmg\bin`, `%LOCALAPPDATA%\safedep\pmg\bin`},
		{"a directory under neither variable stays literal", `D:\tools\pmg\bin`, `D:\tools\pmg\bin`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, machinePathEntry(tt.binDir))
		})
	}
}

// The entry goes after the Windows directories, never ahead of System32,
// and before every directory an installer added.
func TestInsertAfterSystemRoot(t *testing.T) {
	entry := `%LOCALAPPDATA%\safedep\pmg\bin`
	tests := []struct {
		name    string
		entries []string
		want    []string
	}{
		{
			name: "stock machine PATH",
			entries: []string{`%SystemRoot%\system32`, `%SystemRoot%`, `%SystemRoot%\System32\Wbem`,
				`%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\`, `C:\Program Files\nodejs\`},
			want: []string{`%SystemRoot%\system32`, `%SystemRoot%`, `%SystemRoot%\System32\Wbem`,
				`%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\`, entry, `C:\Program Files\nodejs\`},
		},
		{
			name:    "expanded Windows directories count too",
			entries: []string{`C:\WINDOWS\system32`, `C:\Windows`, `C:\Program Files\Git\cmd`},
			want:    []string{`C:\WINDOWS\system32`, `C:\Windows`, entry, `C:\Program Files\Git\cmd`},
		},
		{
			name:    "no Windows directory puts it first",
			entries: []string{`C:\Program Files\nodejs\`},
			want:    []string{entry, `C:\Program Files\nodejs\`},
		},
		{
			name: "empty",
			want: []string{entry},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, insertAfterSystemRoot(tt.entries, entry, `C:\Windows`))
		})
	}
}

func TestMachinePathRegistry(t *testing.T) {
	isolateMachinePath(t)
	entry := `%LOCALAPPDATA%\safedep\pmg\bin`
	binDir := filepath.Join(os.Getenv("LOCALAPPDATA"), `safedep\pmg\bin`)

	t.Run("registers once after the Windows directories and forces REG_EXPAND_SZ", func(t *testing.T) {
		require.NoError(t, writeRawPath(machineEnvironmentRoot, machineEnvironmentKey,
			[]string{`%SystemRoot%\system32`, `C:\Program Files\nodejs\`}, false))

		require.NoError(t, registerMachinePath(entry))
		require.NoError(t, registerMachinePath(entry))

		entries, expand, err := readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
		require.NoError(t, err)
		assert.Equal(t, []string{`%SystemRoot%\system32`, entry, `C:\Program Files\nodejs\`}, entries)
		assert.True(t, expand)

		registered, err := MachinePathRegistered(binDir)
		require.NoError(t, err)
		assert.True(t, registered)
	})

	t.Run("contains folds case and a trailing separator", func(t *testing.T) {
		assert.True(t, containsRawEntry([]string{strings.ToUpper(entry) + `\`}, entry))
		assert.False(t, containsRawEntry([]string{`%LOCALAPPDATA%\safedep\pmg`}, entry))
	})

	t.Run("unregister removes only the entry and keeps the value", func(t *testing.T) {
		require.NoError(t, unregisterMachinePath(entry))
		require.NoError(t, unregisterMachinePath(entry))

		entries, _, err := readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
		require.NoError(t, err)
		assert.Equal(t, []string{`%SystemRoot%\system32`, `C:\Program Files\nodejs\`}, entries)

		registered, err := MachinePathRegistered(binDir)
		require.NoError(t, err)
		assert.False(t, registered)
	})
}

// An elevated install registers the machine entry and an elevated remove
// deletes it. The GitHub Windows runner is elevated, so this runs in CI.
func TestShimManagerElevatedInstallRegistersMachinePath(t *testing.T) {
	if !isElevated() {
		t.Skip("needs an elevated process")
	}
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
	registered, err := MachinePathRegistered(binDir)
	require.NoError(t, err)
	assert.True(t, registered)

	require.NoError(t, mgr.Remove())
	registered, err = MachinePathRegistered(binDir)
	require.NoError(t, err)
	assert.False(t, registered)
}
