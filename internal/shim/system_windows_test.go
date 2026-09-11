//go:build windows

package shim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/platform"
	"github.com/safedep/pmg/internal/winacl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// tempLayout mirrors the Program Files and ProgramData layouts under the
// temp directory: root\pf\safedep\pmg\{pmg.exe,bin} and
// root\pd\safedep\pmg\config.yml.
func tempLayout(t *testing.T) systemLayout {
	t.Helper()
	root := t.TempDir()
	product := filepath.Join(root, "pf", "safedep", "pmg")
	require.NoError(t, os.MkdirAll(product, 0o755))
	configDir := filepath.Join(root, "pd", "safedep", "pmg")
	require.NoError(t, os.MkdirAll(configDir, 0o755))
	layout := systemLayout{
		BinDir:     filepath.Join(product, "bin"),
		ProductDir: product,
		Binary:     filepath.Join(product, "pmg.exe"),
		ConfigFile: filepath.Join(configDir, "config.yml"),
	}
	require.NoError(t, os.WriteFile(layout.Binary, []byte("binary"), 0o755))
	require.NoError(t, os.WriteFile(layout.ConfigFile, []byte("paranoid: true\n"), 0o644))
	return layout
}

// The binary must be the canonical one. Every other location is rejected
// with the path to use.
func TestValidateBinaryRequiresTheCanonicalPath(t *testing.T) {
	layout := tempLayout(t)

	assert.NoError(t, layout.validateBinary(layout.Binary))
	assert.NoError(t, layout.validateBinary(strings.ToUpper(layout.Binary)), "case does not matter on NTFS")

	elsewhere := filepath.Join(t.TempDir(), "pmg.exe")
	require.NoError(t, os.WriteFile(elsewhere, []byte("binary"), 0o755))
	err := layout.validateBinary(elsewhere)
	require.Error(t, err)
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.PermissionDenied, usefulErr.Code())
	assert.Contains(t, usefulErr.HumanError(), layout.Binary)
	assert.Contains(t, usefulErr.Help(), layout.ProductDir)

	assert.ErrorContains(t, layout.validateBinary(filepath.Join(layout.ProductDir, "missing.exe")), "failed to inspect")
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

// useSystemLayout builds a layout under the temp directory and points the
// package-level lookups at it, so ValidateSystemInstall and
// SystemShimsInstalled read the same layout the manager writes. Install
// protects the objects, which needs elevation, so every caller skips
// without it.
func useSystemLayout(t *testing.T) systemLayout {
	t.Helper()
	if !platform.IsPrivileged() {
		t.Skip("Install protects the objects, which needs an elevated process")
	}
	isolateMachinePath(t)
	layout := tempLayout(t)
	systemBinDirOverride = layout.BinDir
	systemConfigFileOverride = layout.ConfigFile
	t.Cleanup(func() { systemBinDirOverride, systemConfigFileOverride = "", "" })

	// The config side is what WriteSystemTemplateConfig leaves behind.
	configDir := filepath.Dir(layout.ConfigFile)
	for _, p := range []string{filepath.Dir(configDir), configDir, layout.ConfigFile} {
		require.NoError(t, winacl.Protect(p))
	}
	return layout
}

func TestSystemShimManagerInstallAndRemove(t *testing.T) {
	layout := useSystemLayout(t)
	setRegistryPath(t, machinePath, `C:\Program Files\nodejs\`)

	mgr := newSystemShimManager(layout, layout.Binary)
	assert.True(t, mgr.config.SkipUserPath)
	assert.NotNil(t, mgr.config.System)
	assert.Equal(t, "", layout.ProfilePath)

	require.NoError(t, mgr.Install())
	assert.True(t, SystemShimsInstalled())
	assert.True(t, layout.pathInstalled())
	binary, err := ValidateSystemInstall()
	require.NoError(t, err, "every object carries the PMG descriptor")
	assert.Equal(t, layout.Binary, binary)

	entries, _, err := machinePath.read()
	require.NoError(t, err)
	assert.Equal(t, []string{layout.BinDir, `C:\Program Files\nodejs\`, layout.ProductDir}, entries,
		"the shim directory goes first and the product directory last, so `pmg` itself resolves")

	content, err := os.ReadFile(filepath.Join(layout.BinDir, "npm.cmd"))
	require.NoError(t, err)
	assert.Contains(t, string(content), layout.Binary)

	// A file an administrator drops next to the shims is not PMG's to judge.
	require.NoError(t, os.WriteFile(filepath.Join(layout.BinDir, "README.txt"), []byte("notes\n"), 0o644))
	_, err = ValidateSystemInstall()
	assert.NoError(t, err, "a foreign file in the shim directory is not a drift")

	// A second install is a no-op on the PATH and rewrites the shims.
	require.NoError(t, mgr.Install())
	entries, _, err = machinePath.read()
	require.NoError(t, err)
	assert.Equal(t, []string{layout.BinDir, `C:\Program Files\nodejs\`, layout.ProductDir}, entries)

	require.NoError(t, mgr.Remove())
	assert.False(t, SystemShimsInstalled())
	assert.False(t, layout.pathInstalled())
	require.NoError(t, mgr.Remove())

	entries, _, err = machinePath.read()
	require.NoError(t, err)
	assert.Equal(t, []string{`C:\Program Files\nodejs\`, layout.ProductDir}, entries, "the binary stays, so its directory stays on PATH")
}

// Doctor reports a drifted descriptor on any object, and a reinstall
// restores it. The drift is applied the way an administrator would, through
// the security API, on a shim, on the shim directory and on the binary.
func TestSystemInstallDetectsAndRepairsDrift(t *testing.T) {
	layout := useSystemLayout(t)
	setRegistryPath(t, machinePath, `C:\Tools`)

	mgr := newSystemShimManager(layout, layout.Binary)
	require.NoError(t, mgr.Install())
	_, err := ValidateSystemInstall()
	require.NoError(t, err)

	loose := "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)"
	looseDir := "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)"
	for _, drift := range []struct{ path, sddl string }{
		{filepath.Join(layout.BinDir, "npm.cmd"), loose},
		{layout.BinDir, looseDir},
		{layout.Binary, loose},
	} {
		applySDDL(t, drift.path, drift.sddl)
		_, err := ValidateSystemInstall()
		require.Error(t, err, drift.path)
		assert.Contains(t, err.Error(), drift.path)

		require.NoError(t, mgr.Install())
		_, err = ValidateSystemInstall()
		assert.NoError(t, err, "reinstall repairs %s", drift.path)
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

// Doctor checks the expected shims by name. A shim that lost its marker,
// and a shim that is gone, are both reported, and a reinstall puts the
// expected set back.
func TestSystemInstallDetectsATamperedOrMissingShim(t *testing.T) {
	layout := useSystemLayout(t)
	setRegistryPath(t, machinePath, `C:\Tools`)
	mgr := newSystemShimManager(layout, layout.Binary)
	require.NoError(t, mgr.Install())

	npm := filepath.Join(layout.BinDir, "npm.cmd")
	require.NoError(t, os.WriteFile(npm, []byte("@echo off\r\necho tampered\r\n"), 0o755))
	applySDDL(t, npm, "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)")
	_, err := ValidateSystemInstall()
	require.Error(t, err)
	assert.Contains(t, err.Error(), npm)

	require.NoError(t, mgr.Install())
	_, err = ValidateSystemInstall()
	require.NoError(t, err)
	content, err := os.ReadFile(npm)
	require.NoError(t, err)
	assert.Contains(t, string(content), "PMG_RAW_ARGS", "the reinstall replaced the tampered shim")

	require.NoError(t, os.Remove(npm))
	_, err = ValidateSystemInstall()
	require.Error(t, err)
	assert.Contains(t, err.Error(), npm)
}

// Doctor's gate is the install's footprint. With every marker stripped the
// shims no longer identify themselves, and the security row must still run
// and still name the shim whose descriptor is wrong. A reinstall leaves no
// temporary sibling behind.
func TestSystemInstallPresentDoesNotDependOnMarkers(t *testing.T) {
	layout := useSystemLayout(t)
	setRegistryPath(t, machinePath, `C:\Tools`)
	mgr := newSystemShimManager(layout, layout.Binary)
	require.NoError(t, mgr.Install())

	shims, err := filepath.Glob(filepath.Join(layout.BinDir, "*.cmd"))
	require.NoError(t, err)
	require.NotEmpty(t, shims)
	for _, shim := range shims {
		require.NoError(t, os.WriteFile(shim, []byte("@echo off\r\necho tampered\r\n"), 0o755))
	}
	assert.False(t, SystemShimsInstalled(), "no shim identifies itself any more")
	assert.True(t, SystemInstallPresent(), "the footprint is still there")

	npm := filepath.Join(layout.BinDir, "npm.cmd")
	applySDDL(t, npm, "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)")
	binary, err := ValidateSystemInstall()
	require.Error(t, err)
	assert.Equal(t, layout.Binary, binary, "the binary comes from the layout, not from a shim")
	assert.Contains(t, err.Error(), npm)

	require.NoError(t, mgr.Install())
	_, err = ValidateSystemInstall()
	require.NoError(t, err)
	leftovers, err := filepath.Glob(filepath.Join(layout.BinDir, "*.tmp"))
	require.NoError(t, err)
	assert.Empty(t, leftovers)
}

// A link planted under a shim's name must not be followed. The install
// removes the link and writes a regular file, and the link's target is
// untouched.
func TestSystemInstallReplacesAPlantedLink(t *testing.T) {
	layout := useSystemLayout(t)
	setRegistryPath(t, machinePath, `C:\Tools`)
	require.NoError(t, os.MkdirAll(layout.BinDir, 0o755))
	decoy := filepath.Join(t.TempDir(), "decoy.cmd")
	require.NoError(t, os.WriteFile(decoy, []byte("decoy\r\n"), 0o644))
	npm := filepath.Join(layout.BinDir, "npm.cmd")
	require.NoError(t, os.Symlink(decoy, npm))

	require.NoError(t, newSystemShimManager(layout, layout.Binary).Install())

	info, err := os.Lstat(npm)
	require.NoError(t, err)
	assert.True(t, info.Mode().IsRegular(), "the link was replaced by a file")
	decoyContent, err := os.ReadFile(decoy)
	require.NoError(t, err)
	assert.Equal(t, "decoy\r\n", string(decoyContent), "the link's target was not written through")
	_, err = ValidateSystemInstall()
	assert.NoError(t, err)
}

// Doctor checks the managed config and both of its directories, and
// treats a missing file as a failure while system shims exist.
func TestSystemInstallChecksTheManagedConfig(t *testing.T) {
	layout := useSystemLayout(t)
	setRegistryPath(t, machinePath, `C:\Tools`)
	require.NoError(t, newSystemShimManager(layout, layout.Binary).Install())
	_, err := ValidateSystemInstall()
	require.NoError(t, err)

	applySDDL(t, layout.ConfigFile, "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;FW;;;BU)")
	_, err = ValidateSystemInstall()
	require.Error(t, err)
	assert.Contains(t, err.Error(), layout.ConfigFile)
	require.NoError(t, winacl.Protect(layout.ConfigFile))

	configDir := filepath.Dir(layout.ConfigFile)
	applySDDL(t, filepath.Dir(configDir), "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)")
	_, err = ValidateSystemInstall()
	require.Error(t, err)
	assert.Contains(t, err.Error(), filepath.Dir(configDir))
	require.NoError(t, winacl.Protect(filepath.Dir(configDir)))

	require.NoError(t, os.Remove(layout.ConfigFile))
	_, err = ValidateSystemInstall()
	assert.Error(t, err, "a missing managed config is not health while system shims exist")
}
