//go:build windows

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// secureManagedConfigForTest gives a test's managed config directory, the
// directory above it, and the file when one exists, the descriptor the
// install writes, so the runtime rule accepts the file. Setting the owner
// needs elevation.
func secureManagedConfigForTest(t *testing.T, dir string) {
	t.Helper()
	if !platform.IsPrivileged() {
		t.Skip("a managed config the runtime trusts needs an elevated process to create")
	}
	require.NoError(t, platform.ProtectSystemPath(filepath.Dir(dir), 0o755))
	require.NoError(t, platform.ProtectSystemPath(dir, 0o755))
	file := filepath.Join(dir, "config.yml")
	if _, err := os.Stat(file); err == nil {
		require.NoError(t, platform.ProtectSystemPath(file, 0o644))
	}
}

func useGlobalConfigDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "safedep", "pmg")
	globalConfigDirOverride = dir
	t.Cleanup(func() { globalConfigDirOverride = "" })
	return dir
}

// A junction in place of the managed directory would send the writes and
// the descriptor changes to a target of the user's choosing. It is rejected
// before anything is protected or written.
func TestWriteSystemTemplateConfigRejectsAJunction(t *testing.T) {
	dir := useGlobalConfigDir(t)
	target := filepath.Join(t.TempDir(), "elsewhere")
	require.NoError(t, os.MkdirAll(target, 0o755))
	require.NoError(t, os.MkdirAll(filepath.Dir(dir), 0o755))
	require.NoError(t, exec.Command("cmd", "/c", "mklink", "/J", dir, target).Run())

	err := WriteSystemTemplateConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "link or a junction")
	assert.NoFileExists(t, filepath.Join(target, "config.yml"))
}

// A config a standard user dropped into the managed path before setup must
// not seed the machine policy. The file carries the directory's inherited
// descriptor, not PMG's, which is the shape of that attack. The directories
// are secured first, then the file is rejected before it is read, and left
// in place.
func TestWriteSystemTemplateConfigRejectsAnUntrustedExistingFile(t *testing.T) {
	if !platform.IsPrivileged() {
		t.Skip("securing the directories needs an elevated process")
	}
	dir := useGlobalConfigDir(t)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path := filepath.Join(dir, "config.yml")
	require.NoError(t, os.WriteFile(path, []byte("paranoid: false\n"), 0o644))

	err := WriteSystemTemplateConfig()
	require.Error(t, err)
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.PermissionDenied, usefulErr.Code())
	assert.Contains(t, usefulErr.HumanError(), path)
	assert.Contains(t, usefulErr.Help(), "Inspect the file, delete it, and run the install again")
	assert.Contains(t, err.Error(), "does not carry the PMG security descriptor")

	assert.NoError(t, platform.RequireProtected(dir), "the directories are secured before the file is checked")
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "paranoid: false\n", string(content), "the file is left as evidence")
}

// The runtime obeys the managed config only when Administrators or SYSTEM
// own it and nobody else may write it. A file the install protected
// governs. The same file with a write grant for Users is ignored. A junction
// at the path is not a regular file and never governs.
func TestResolveConfigFileTrustsAdministrativeControl(t *testing.T) {
	if !platform.IsPrivileged() {
		t.Skip("a file with an administrative owner needs an elevated process")
	}
	dir := useGlobalConfigDir(t)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path := filepath.Join(dir, "config.yml")
	require.NoError(t, os.WriteFile(path, []byte("paranoid: true\n"), 0o644))
	for _, p := range []string{filepath.Dir(dir), dir, path} {
		require.NoError(t, platform.ProtectSystemPath(p, 0o755))
	}

	got, err := resolveConfigFile()
	require.NoError(t, err)
	assert.Equal(t, path, got)

	loosened, err := windows.SecurityDescriptorFromString("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;FW;;;BU)")
	require.NoError(t, err)
	owner, _, err := loosened.Owner()
	require.NoError(t, err)
	dacl, _, err := loosened.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil))
	got, err = resolveConfigFile()
	require.NoError(t, err)
	assert.NotEqual(t, path, got, "a managed config Users may write is ignored")

	require.NoError(t, os.Remove(path))
	target := filepath.Join(t.TempDir(), "elsewhere")
	require.NoError(t, os.MkdirAll(target, 0o755))
	require.NoError(t, exec.Command("cmd", "/c", "mklink", "/J", path, target).Run())

	got, err = resolveConfigFile()
	require.NoError(t, err)
	assert.NotEqual(t, path, got, "a junction at the managed path is ignored")
}

// The runtime trusts the file only with both directories above it under
// administrative control. A parent a standard user may write into is a
// parent whose entries they can swap.
func TestResolveConfigFileRequiresControlledParents(t *testing.T) {
	if !platform.IsPrivileged() {
		t.Skip("a protected directory needs an elevated process")
	}
	dir := useGlobalConfigDir(t)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path := filepath.Join(dir, "config.yml")
	require.NoError(t, os.WriteFile(path, []byte("paranoid: true\n"), 0o644))
	for _, p := range []string{filepath.Dir(dir), dir, path} {
		require.NoError(t, platform.ProtectSystemPath(p, 0o755))
	}
	got, err := resolveConfigFile()
	require.NoError(t, err)
	require.Equal(t, path, got)

	applySDDL(t, filepath.Dir(dir), "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)")
	got, err = resolveConfigFile()
	require.NoError(t, err)
	assert.NotEqual(t, path, got, "a managed config under a directory Users may write is ignored")
}

// Removal by name would follow a junction planted in place of the product
// directory and delete a file of the planter's choosing. Removal refuses.
func TestRemoveSystemConfigFileRefusesAJunctionParent(t *testing.T) {
	dir := useGlobalConfigDir(t)
	target := filepath.Join(t.TempDir(), "elsewhere")
	require.NoError(t, os.MkdirAll(target, 0o755))
	victim := filepath.Join(target, "config.yml")
	require.NoError(t, os.WriteFile(victim, []byte("theirs\n"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Dir(dir), 0o755))
	require.NoError(t, exec.Command("cmd", "/c", "mklink", "/J", dir, target).Run())

	err := RemoveSystemConfigFile()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to remove")
	assert.FileExists(t, victim, "the junction target was not touched")
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

// The elevated path. A fresh install protects the vendor directory, the
// product directory and the file it writes. A second run merges the file,
// because it carries the PMG descriptor. A file whose descriptor drifted
// after that is rejected again.
func TestWriteSystemTemplateConfigProtectsWhatItWrites(t *testing.T) {
	if !platform.IsPrivileged() {
		t.Skip("setting the owner needs an elevated process")
	}
	dir := useGlobalConfigDir(t)
	path := filepath.Join(dir, "config.yml")

	require.NoError(t, WriteSystemTemplateConfig())
	assert.NoError(t, platform.RequireProtected(filepath.Dir(dir)))
	assert.NoError(t, platform.RequireProtected(dir))
	assert.NoError(t, platform.RequireProtected(path))

	require.NoError(t, WriteSystemTemplateConfig())
	assert.NoError(t, platform.RequireProtected(path))

	drifted, err := windows.SecurityDescriptorFromString("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;FW;;;BU)")
	require.NoError(t, err)
	owner, _, err := drifted.Owner()
	require.NoError(t, err)
	dacl, _, err := drifted.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil))

	err = WriteSystemTemplateConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has 4 entries, not 3")
}
