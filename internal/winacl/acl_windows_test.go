//go:build windows

package winacl

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// compare runs on descriptors built from SDDL, so every case runs without
// elevation. BA is Administrators, SY is SYSTEM, BU is Users, WD is
// Everyone. FA is full access, FW write, 0x1200a9 read and execute. A is
// allow, D is deny. P marks a protected DACL, OICI object and container
// inherit.
func TestCompare(t *testing.T) {
	tests := []struct {
		name    string
		sddl    string
		isDir   bool
		wantErr string
	}{
		{name: "the PMG file descriptor", sddl: protectedFileSDDL},
		{name: "the PMG directory descriptor", sddl: protectedDirSDDL, isDir: true},
		{name: "a different owner", sddl: "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)", wantErr: "the owner is S-1-5-18, not Administrators"},
		{name: "no owner", sddl: "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)", wantErr: "it has no owner"},
		{name: "an inheriting DACL", sddl: "O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)", wantErr: "inherits from the parent"},
		{name: "no DACL", sddl: "O:BA", wantErr: "has no DACL"},
		{name: "an extra write entry", sddl: "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;FW;;;WD)", wantErr: "has 4 entries, not 3"},
		{name: "a missing Users entry", sddl: "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)", wantErr: "has 2 entries, not 3"},
		{name: "Users may write instead of read", sddl: "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)", wantErr: "entry 3 differs"},
		{name: "a different order", sddl: "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)", wantErr: "entry 1 differs"},
		{name: "a deny entry in place of an allow", sddl: "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(D;;0x1200a9;;;BU)", wantErr: "entry 3 differs"},
		{name: "file flags on a directory", sddl: protectedFileSDDL, isDir: true, wantErr: "entry 1 differs"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := windows.SecurityDescriptorFromString(tt.sddl)
			require.NoError(t, err)
			want, err := expected(tt.isDir)
			require.NoError(t, err)

			err = compare(got, want)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestRequireNotReparsePoint(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(target, 0o755))

	assert.NoError(t, RequireNotReparsePoint(target))
	assert.NoError(t, RequireNotReparsePoint(filepath.Join(dir, "missing")))

	// A junction needs no privilege, unlike a symbolic link.
	link := filepath.Join(dir, "link")
	require.NoError(t, exec.Command("cmd", "/c", "mklink", "/J", link, target).Run())
	assert.ErrorContains(t, RequireNotReparsePoint(link), "link or a junction")
	assert.ErrorContains(t, RequireProtected(link), "link or a junction")
}

// A file the test created carries the temp directory's inherited descriptor,
// which is what a file a standard user dropped in looks like.
func TestRequireTrustedExistingRejectsWhatPMGDidNotWrite(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.yml")
	assert.NoError(t, RequireTrustedExisting(file), "a missing file passes")

	require.NoError(t, os.WriteFile(file, []byte("paranoid: false\n"), 0o644))
	assert.ErrorContains(t, RequireTrustedExisting(file), "does not carry the PMG security descriptor")

	assert.ErrorContains(t, RequireTrustedExisting(dir), "not a regular file")
}

func TestProtectRefusesWithoutElevation(t *testing.T) {
	if ProcessIsElevated() {
		t.Skip("the process is elevated")
	}
	file := filepath.Join(t.TempDir(), "npm.cmd")
	require.NoError(t, os.WriteFile(file, nil, 0o755))
	assert.ErrorContains(t, Protect(file), "not elevated")
}

// The round trip through Windows: Protect writes the descriptor,
// RequireProtected reads it back and finds it exact, for a directory and a
// file. Then a drift is applied and repaired. Setting the owner needs
// elevation, which the CI runner has.
func TestProtectRoundTripAndRepair(t *testing.T) {
	if !ProcessIsElevated() {
		t.Skip("needs an elevated process")
	}
	dir := filepath.Join(t.TempDir(), "pmg")
	require.NoError(t, os.Mkdir(dir, 0o755))
	file := filepath.Join(dir, "npm.cmd")
	require.NoError(t, os.WriteFile(file, []byte("@echo off\r\n"), 0o755))
	require.Error(t, RequireProtected(dir))
	require.Error(t, RequireProtected(file))

	require.NoError(t, Protect(dir))
	require.NoError(t, Protect(file))
	assert.NoError(t, RequireProtected(dir))
	assert.NoError(t, RequireProtected(file))
	assert.NoError(t, RequireTrustedExisting(file))

	applySDDL(t, file, "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;FW;;;BU)")
	assert.ErrorContains(t, RequireProtected(file), "has 4 entries, not 3")

	require.NoError(t, Protect(file))
	assert.NoError(t, RequireProtected(file))
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
