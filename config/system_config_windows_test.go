//go:build windows

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/internal/winacl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func useGlobalConfigDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "safedep", "pmg")
	globalConfigDirOverride = dir
	t.Cleanup(func() { globalConfigDirOverride = "" })
	return dir
}

// The managed config directory comes from the shell, not from a variable
// the user's process controls.
func TestGlobalConfigDirIgnoresTheEnvironment(t *testing.T) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	require.NoError(t, err)

	t.Setenv("PROGRAMDATA", `C:\Users\dev\evil`)
	assert.Equal(t, filepath.Join(programData, `safedep\pmg`), globalConfigDir())
}

// A config a standard user dropped into the managed path before setup must
// not seed the machine policy. The file in the temp directory carries the
// directory's inherited descriptor, not PMG's, which is the shape of that
// attack. It is rejected before it is read, and left in place.
func TestWriteSystemTemplateConfigRejectsAnUntrustedExistingFile(t *testing.T) {
	dir := useGlobalConfigDir(t)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path := filepath.Join(dir, "config.yml")
	require.NoError(t, os.WriteFile(path, []byte("paranoid: false\n"), 0o644))

	err := WriteSystemTemplateConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not carry the PMG security descriptor")
	assert.Contains(t, err.Error(), "Inspect the file, delete it, and run the install again")

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "paranoid: false\n", string(content), "the file is left as evidence")
}

// A junction in place of the managed directory would send the writes and
// the descriptor changes to a target of the user's choosing.
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

// The elevated path. A fresh install protects the vendor directory, the
// product directory and the file it writes. A second run merges the file,
// because it carries the PMG descriptor. A file whose descriptor drifted
// after that is rejected again.
func TestWriteSystemTemplateConfigProtectsWhatItWrites(t *testing.T) {
	if !winacl.ProcessIsElevated() {
		t.Skip("setting the owner needs an elevated process")
	}
	dir := useGlobalConfigDir(t)
	path := filepath.Join(dir, "config.yml")

	require.NoError(t, WriteSystemTemplateConfig())
	assert.NoError(t, winacl.RequireProtected(filepath.Dir(dir)))
	assert.NoError(t, winacl.RequireProtected(dir))
	assert.NoError(t, winacl.RequireProtected(path))

	require.NoError(t, WriteSystemTemplateConfig())
	assert.NoError(t, winacl.RequireProtected(path))

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
