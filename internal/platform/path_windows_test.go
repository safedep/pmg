package platform

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

// redirectUserPath points the user PATH scope at a throwaway key, so a test
// never edits the real HKCU\Environment.
func redirectUserPath(t *testing.T) {
	t.Helper()
	restore, err := RedirectUserPathForTest(`Software\pmg-plat-test-` + strings.ReplaceAll(t.Name(), "/", "_"))
	require.NoError(t, err)
	t.Cleanup(restore)
}

func redirectMachinePath(t *testing.T) {
	t.Helper()
	restore, err := RedirectMachinePathForTest(`Software\pmg-plat-test-machine-` + strings.ReplaceAll(t.Name(), "/", "_"))
	require.NoError(t, err)
	t.Cleanup(restore)
}

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

func TestUserPathRegistry(t *testing.T) {
	redirectUserPath(t)
	shimDir := `C:\Users\dev\AppData\Local\safedep\pmg\bin`

	t.Run("prepends once and keeps the value type", func(t *testing.T) {
		// Windows writes the default user PATH as REG_EXPAND_SZ so
		// %USERPROFILE% style entries stay unexpanded.
		require.NoError(t, UserPath.write([]string{`%USERPROFILE%\bin`, `C:\Tools`}, true))

		require.NoError(t, UserPath.Prepend(shimDir))
		require.NoError(t, UserPath.Prepend(shimDir))

		entries, expand, err := UserPath.read()
		require.NoError(t, err)
		assert.Equal(t, []string{shimDir, `%USERPROFILE%\bin`, `C:\Tools`}, entries)
		assert.True(t, expand)
	})

	t.Run("contains folds case", func(t *testing.T) {
		found, err := UserPath.Contains(strings.ToUpper(shimDir))
		require.NoError(t, err)
		assert.True(t, found)
	})

	t.Run("removes only the shim entry", func(t *testing.T) {
		require.NoError(t, UserPath.Remove(strings.ToLower(shimDir)))

		entries, _, err := UserPath.read()
		require.NoError(t, err)
		assert.Equal(t, []string{`%USERPROFILE%\bin`, `C:\Tools`}, entries)

		found, err := UserPath.Contains(shimDir)
		require.NoError(t, err)
		assert.False(t, found)
	})

	t.Run("a missing Path value reads as empty", func(t *testing.T) {
		key, err := registry.OpenKey(registry.CURRENT_USER, UserPath.key, registry.SET_VALUE)
		require.NoError(t, err)
		require.NoError(t, key.DeleteValue(pathValueName))
		require.NoError(t, key.Close())

		entries, _, err := UserPath.read()
		require.NoError(t, err)
		assert.Empty(t, entries)

		require.NoError(t, UserPath.Prepend(shimDir))
		found, err := UserPath.Contains(shimDir)
		require.NoError(t, err)
		assert.True(t, found)
	})

	t.Run("removing the only entry leaves no value behind", func(t *testing.T) {
		require.NoError(t, UserPath.Remove(shimDir))

		key, err := registry.OpenKey(registry.CURRENT_USER, UserPath.key, registry.QUERY_VALUE)
		require.NoError(t, err)
		defer key.Close()
		_, _, err = key.GetStringValue(pathValueName)
		assert.ErrorIs(t, err, registry.ErrNotExist)
	})
}

// Prepend moves the shim directory to the front when an installer prepended
// its own directory after the last `pmg setup install`.
func TestPrependMovesTheShimDirectoryToTheFront(t *testing.T) {
	redirectUserPath(t)
	shimDir := `C:\Users\dev\AppData\Local\safedep\pmg\bin`
	pythonDir := `C:\Users\dev\AppData\Local\Programs\Python\Python312\Scripts`

	require.NoError(t, UserPath.write([]string{pythonDir, shimDir, `C:\Tools`}, true))
	require.NoError(t, UserPath.Prepend(shimDir))

	entries, _, err := UserPath.read()
	require.NoError(t, err)
	assert.Equal(t, []string{shimDir, pythonDir, `C:\Tools`}, entries)

	require.NoError(t, UserPath.Prepend(shimDir))
	entries, _, err = UserPath.read()
	require.NoError(t, err)
	assert.Equal(t, []string{shimDir, pythonDir, `C:\Tools`}, entries)
}

// NewShellPath reads the machine half then the user half, expanding %VAR%
// from this process's environment and stripping the quotes an entry carries.
func TestNewShellPathReadsBothHalves(t *testing.T) {
	redirectUserPath(t)
	redirectMachinePath(t)
	require.NoError(t, MachinePath.write([]string{`C:\Program Files\nodejs`, `%SystemRoot%\System32`}, true))
	require.NoError(t, UserPath.write([]string{`%LOCALAPPDATA%\safedep\pmg\bin`, `"C:\Quoted Tools"`}, true))

	shell, err := NewShellPath()
	require.NoError(t, err)

	assert.Equal(t, []string{
		`C:\Program Files\nodejs`,
		filepath.Join(os.Getenv("SystemRoot"), "System32"),
	}, shell.machine, "%VAR% expands from this process's environment")
	assert.Equal(t, []string{
		filepath.Join(os.Getenv("LOCALAPPDATA"), `safedep\pmg\bin`),
		`C:\Quoted Tools`,
	}, shell.user, "SplitList strips the quotes a PATH entry may carry")
	assert.Equal(t, append(append([]string{}, shell.machine...), shell.user...), shell.Entries)
}

// LookPath resolves a name the way a shell would and reports which PATH
// source held the winning directory. Each case writes both registry halves
// and the process PATH, so the runner's own PATH cannot reach the result.
func TestShellPathLookPath(t *testing.T) {
	newManagerDir := func(t *testing.T, names ...string) string {
		t.Helper()
		dir := t.TempDir()
		for _, name := range names {
			require.NoError(t, os.WriteFile(filepath.Join(dir, name+".cmd"), nil, 0o644))
		}
		return dir
	}
	joinPath := func(dirs ...string) string { return strings.Join(dirs, ";") }

	// Windows builds a process PATH as the machine value, then the user value,
	// so a manager a machine-wide installer put on PATH resolves before a
	// user-scope shim. Its origin decides the remedy.
	t.Run("machine PATH resolves before the user PATH", func(t *testing.T) {
		redirectUserPath(t)
		redirectMachinePath(t)
		machineDir := newManagerDir(t, "npm")
		shimDir := newManagerDir(t, "npm", "pnpm")

		require.NoError(t, MachinePath.write([]string{machineDir}, true))
		require.NoError(t, UserPath.write([]string{shimDir}, true))
		t.Setenv("PATH", joinPath(machineDir, shimDir))

		shell, err := NewShellPath()
		require.NoError(t, err)
		assert.Equal(t, []string{machineDir, shimDir}, shell.Entries)

		path, origin, err := shell.LookPath("npm")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(machineDir, "npm.cmd"), path)
		assert.Equal(t, PathOriginMachine, origin)

		path, origin, err = shell.LookPath("pnpm")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(shimDir, "pnpm.cmd"), path)
		assert.Equal(t, PathOriginUser, origin)
	})

	// The user half is the one PMG can reorder, so a manager shadowed from
	// there gets a different remedy.
	t.Run("a user PATH entry ahead of the shims", func(t *testing.T) {
		redirectUserPath(t)
		redirectMachinePath(t)
		pythonDir := newManagerDir(t, "pip")
		shimDir := newManagerDir(t, "pip")

		require.NoError(t, MachinePath.write([]string{`C:\Windows\System32`}, true))
		require.NoError(t, UserPath.write([]string{pythonDir, shimDir}, true))
		t.Setenv("PATH", joinPath(`C:\Windows\System32`, pythonDir, shimDir))

		shell, err := NewShellPath()
		require.NoError(t, err)
		path, origin, err := shell.LookPath("pip")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(pythonDir, "pip.cmd"), path)
		assert.Equal(t, PathOriginUser, origin)
	})

	// `fnm env | Invoke-Expression` in $PROFILE prepends a directory that
	// holds npm. The registry never sees it, so reading the registry alone
	// would report the shims as winning in a shell where they do not.
	t.Run("a shell profile ahead of the shims", func(t *testing.T) {
		redirectUserPath(t)
		redirectMachinePath(t)
		profileDir := newManagerDir(t, "npm")
		shimDir := newManagerDir(t, "npm")

		require.NoError(t, MachinePath.write([]string{`C:\Windows\System32`}, true))
		require.NoError(t, UserPath.write([]string{shimDir}, true))
		t.Setenv("PATH", joinPath(profileDir, `C:\Windows\System32`, shimDir))

		shell, err := NewShellPath()
		require.NoError(t, err)
		path, origin, err := shell.LookPath("npm")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(profileDir, "npm.cmd"), path)
		assert.Equal(t, PathOriginProfile, origin)
	})

	// Doctor often runs in the shell that ran `pmg setup install`, whose
	// process PATH predates the registry write. The registry answer stands,
	// because every directory that shell resolves from is in the registry.
	t.Run("a stale shell keeps the registry answer", func(t *testing.T) {
		redirectUserPath(t)
		redirectMachinePath(t)
		nodeDir := newManagerDir(t, "npm")
		shimDir := newManagerDir(t, "npm")

		require.NoError(t, MachinePath.write([]string{nodeDir}, true))
		require.NoError(t, UserPath.write([]string{shimDir}, true))
		t.Setenv("PATH", nodeDir)

		shell, err := NewShellPath()
		require.NoError(t, err)
		path, origin, err := shell.LookPath("npm")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(nodeDir, "npm.cmd"), path)
		assert.Equal(t, PathOriginMachine, origin)
	})
}

func TestMachinePathScope(t *testing.T) {
	redirectMachinePath(t)
	shimDir := `C:\Program Files\safedep\pmg\bin`

	t.Run("prepends once and keeps the value type", func(t *testing.T) {
		require.NoError(t, MachinePath.write([]string{`%SystemRoot%\system32`, `C:\Program Files\nodejs\`}, true))

		require.NoError(t, MachinePath.Prepend(shimDir))
		require.NoError(t, MachinePath.Prepend(shimDir))

		entries, expand, err := MachinePath.read()
		require.NoError(t, err)
		assert.Equal(t, []string{shimDir, `%SystemRoot%\system32`, `C:\Program Files\nodejs\`}, entries)
		assert.True(t, expand)
	})

	t.Run("moves the directory back to the front", func(t *testing.T) {
		require.NoError(t, MachinePath.write([]string{`C:\Program Files\nodejs\`, shimDir + `\`}, true))

		require.NoError(t, MachinePath.Prepend(shimDir))

		entries, _, err := MachinePath.read()
		require.NoError(t, err)
		assert.Equal(t, []string{shimDir, `C:\Program Files\nodejs\`}, entries)
	})

	t.Run("an entry written through a variable counts as present", func(t *testing.T) {
		require.NoError(t, MachinePath.write([]string{`%ProgramFiles%\safedep\pmg\bin`, `C:\Tools`}, true))

		found, err := MachinePath.Contains(filepath.Join(os.Getenv("ProgramFiles"), `safedep\pmg\bin`))
		require.NoError(t, err)
		assert.True(t, found)
	})

	t.Run("append adds once at the end and moves nothing", func(t *testing.T) {
		require.NoError(t, MachinePath.write([]string{shimDir, `C:\Tools`}, true))

		require.NoError(t, MachinePath.Append(`C:\Program Files\safedep\pmg`))
		require.NoError(t, MachinePath.Append(`C:\Program Files\safedep\pmg`))
		require.NoError(t, MachinePath.Append(`c:\tools`))

		entries, _, err := MachinePath.read()
		require.NoError(t, err)
		assert.Equal(t, []string{shimDir, `C:\Tools`, `C:\Program Files\safedep\pmg`}, entries)
	})

	t.Run("remove drops only the directory and never the value", func(t *testing.T) {
		require.NoError(t, MachinePath.write([]string{shimDir, `C:\Tools`}, false))

		require.NoError(t, MachinePath.Remove(strings.ToLower(shimDir)))
		require.NoError(t, MachinePath.Remove(shimDir))

		entries, expand, err := MachinePath.read()
		require.NoError(t, err)
		assert.Equal(t, []string{`C:\Tools`}, entries)
		assert.False(t, expand, "a REG_SZ value stays REG_SZ")

		require.NoError(t, MachinePath.Remove(`C:\Tools`))
		entries, _, err = MachinePath.read()
		require.NoError(t, err)
		assert.Empty(t, entries)
	})
}
