//go:build windows

package shim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safedep/pmg/internal/winacl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

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

// The binary must be the canonical one. Every other location is rejected
// with the path to use.
func TestValidateSystemExecutableRequiresTheCanonicalPath(t *testing.T) {
	root := t.TempDir()
	systemBinDirOverride = filepath.Join(root, "bin")
	t.Cleanup(func() { systemBinDirOverride = "" })

	canonical := filepath.Join(root, "pmg.exe")
	require.NoError(t, os.WriteFile(canonical, []byte("binary"), 0o755))
	assert.NoError(t, validateSystemExecutable(canonical))
	assert.NoError(t, validateSystemExecutable(strings.ToUpper(canonical)), "case does not matter on NTFS")

	elsewhere := filepath.Join(t.TempDir(), "pmg.exe")
	require.NoError(t, os.WriteFile(elsewhere, []byte("binary"), 0o755))
	err := validateSystemExecutable(elsewhere)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "A system install needs it at "+canonical)

	assert.ErrorContains(t, validateSystemExecutable(filepath.Join(root, "missing.exe")), "failed to inspect")
}

func TestMachinePathScope(t *testing.T) {
	isolateMachinePath(t)
	shimDir := `C:\Program Files\safedep\pmg\bin`

	t.Run("prepends once and keeps the value type", func(t *testing.T) {
		setRegistryPath(t, machinePath, `%SystemRoot%\system32;C:\Program Files\nodejs\`)

		require.NoError(t, machinePath.prepend(shimDir))
		require.NoError(t, machinePath.prepend(shimDir))

		entries, expand, err := machinePath.read()
		require.NoError(t, err)
		assert.Equal(t, []string{shimDir, `%SystemRoot%\system32`, `C:\Program Files\nodejs\`}, entries)
		assert.True(t, expand)
	})

	t.Run("moves the directory back to the front", func(t *testing.T) {
		require.NoError(t, machinePath.write([]string{`C:\Program Files\nodejs\`, shimDir + `\`}, true))

		require.NoError(t, machinePath.prepend(shimDir))

		entries, _, err := machinePath.read()
		require.NoError(t, err)
		assert.Equal(t, []string{shimDir, `C:\Program Files\nodejs\`}, entries)
	})

	t.Run("an entry written through a variable counts as present", func(t *testing.T) {
		require.NoError(t, machinePath.write([]string{`%ProgramFiles%\safedep\pmg\bin`, `C:\Tools`}, true))

		found, err := machinePath.contains(filepath.Join(os.Getenv("ProgramFiles"), `safedep\pmg\bin`))
		require.NoError(t, err)
		assert.True(t, found)
	})

	t.Run("append adds once at the end and moves nothing", func(t *testing.T) {
		require.NoError(t, machinePath.write([]string{shimDir, `C:\Tools`}, true))

		require.NoError(t, machinePath.append(`C:\Program Files\safedep\pmg`))
		require.NoError(t, machinePath.append(`C:\Program Files\safedep\pmg`))
		require.NoError(t, machinePath.append(`c:\tools`))

		entries, _, err := machinePath.read()
		require.NoError(t, err)
		assert.Equal(t, []string{shimDir, `C:\Tools`, `C:\Program Files\safedep\pmg`}, entries)
	})

	t.Run("remove drops only the directory and never the value", func(t *testing.T) {
		require.NoError(t, machinePath.write([]string{shimDir, `C:\Tools`}, false))

		require.NoError(t, machinePath.remove(strings.ToLower(shimDir)))
		require.NoError(t, machinePath.remove(shimDir))

		entries, expand, err := machinePath.read()
		require.NoError(t, err)
		assert.Equal(t, []string{`C:\Tools`}, entries)
		assert.False(t, expand, "a REG_SZ value stays REG_SZ")

		require.NoError(t, machinePath.remove(`C:\Tools`))
		entries, _, err = machinePath.read()
		require.NoError(t, err)
		assert.Empty(t, entries)
	})
}

// useSystemPaths is the Windows twin of the Unix helper. The layout under
// the temp directory mirrors Program Files: root\safedep\pmg\pmg.exe and
// root\safedep\pmg\bin. Install protects the objects, which needs elevation,
// so every caller skips without it.
func useSystemPaths(t *testing.T) string {
	t.Helper()
	if !winacl.ProcessIsElevated() {
		t.Skip("Install protects the objects, which needs an elevated process")
	}
	isolateMachinePath(t)
	product := filepath.Join(t.TempDir(), "safedep", "pmg")
	require.NoError(t, os.MkdirAll(product, 0o755))
	systemBinDirOverride = filepath.Join(product, "bin")

	exe := filepath.Join(product, "pmg.exe")
	require.NoError(t, os.WriteFile(exe, []byte("binary"), 0o755))
	resolveExecutable = func() (string, error) { return exe, nil }

	t.Cleanup(func() {
		systemBinDirOverride = ""
		resolveExecutable = currentExecutable
	})
	return product
}

func TestSystemShimManagerInstallAndRemove(t *testing.T) {
	product := useSystemPaths(t)
	setRegistryPath(t, machinePath, `C:\Program Files\nodejs\`)

	mgr, err := NewSystemShimManager()
	require.NoError(t, err)
	assert.True(t, mgr.config.SkipUserPath)
	assert.True(t, mgr.config.SystemProfile)
	assert.Equal(t, "", SystemProfilePath())

	require.NoError(t, mgr.Install())
	assert.True(t, SystemShimsInstalled())
	assert.True(t, SystemPathInstalled())
	assert.NoError(t, ValidateSystemInstall(), "every object carries the PMG descriptor")

	entries, _, err := machinePath.read()
	require.NoError(t, err)
	assert.Equal(t, []string{SystemBinDir(), `C:\Program Files\nodejs\`, product}, entries,
		"the shim directory goes first and the product directory last, so `pmg` itself resolves")

	content, err := os.ReadFile(filepath.Join(SystemBinDir(), "npm.cmd"))
	require.NoError(t, err)
	assert.Contains(t, string(content), filepath.Join(product, "pmg.exe"))

	bin, ok := SystemShimBinary()
	require.True(t, ok)
	assert.Equal(t, filepath.Join(product, "pmg.exe"), bin)

	// A second install is a no-op on the PATH and rewrites the shims.
	require.NoError(t, mgr.Install())
	entries, _, err = machinePath.read()
	require.NoError(t, err)
	assert.Equal(t, []string{SystemBinDir(), `C:\Program Files\nodejs\`, product}, entries)

	require.NoError(t, mgr.Remove())
	assert.False(t, SystemShimsInstalled())
	assert.False(t, SystemPathInstalled())
	require.NoError(t, mgr.Remove())

	entries, _, err = machinePath.read()
	require.NoError(t, err)
	assert.Equal(t, []string{`C:\Program Files\nodejs\`, product}, entries, "the binary stays, so its directory stays on PATH")
}

// Doctor reports a drifted descriptor on any object, and a reinstall
// restores it. The drift is applied the way an administrator would, through
// the security API, on a shim, on the shim directory and on the binary.
func TestSystemInstallDetectsAndRepairsDrift(t *testing.T) {
	product := useSystemPaths(t)
	setRegistryPath(t, machinePath, `C:\Tools`)

	mgr, err := NewSystemShimManager()
	require.NoError(t, err)
	require.NoError(t, mgr.Install())
	require.NoError(t, ValidateSystemInstall())

	loose := "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)"
	looseDir := "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)"
	for _, drift := range []struct{ path, sddl string }{
		{filepath.Join(SystemBinDir(), "npm.cmd"), loose},
		{SystemBinDir(), looseDir},
		{filepath.Join(product, "pmg.exe"), loose},
	} {
		applySDDL(t, drift.path, drift.sddl)
		err := ValidateSystemInstall()
		require.Error(t, err, drift.path)
		assert.Contains(t, err.Error(), drift.path)

		require.NoError(t, mgr.Install())
		assert.NoError(t, ValidateSystemInstall(), "reinstall repairs %s", drift.path)
	}
}

func applySDDL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	require.NoError(t, err)
	owner, _, err := sd.Owner()
	require.NoError(t, err)
	dacl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil))
}
