package platform

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
		{name: "Users may write instead of read", sddl: "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)", wantErr: "DACL entry 3 of the PMG descriptor is missing or changed"},
		{name: "a different order is the same set", sddl: "O:BAD:P(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;FA;;;SY)"},
		{name: "a deny entry in place of an allow", sddl: "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(D;;0x1200a9;;;BU)", wantErr: "DACL entry 3 of the PMG descriptor is missing or changed"},
		{name: "one entry twice in place of another", sddl: "O:BAD:P(A;;FA;;;SY)(A;;FA;;;SY)(A;;0x1200a9;;;BU)", wantErr: "DACL entry 2 of the PMG descriptor is missing or changed"},
		{name: "file flags on a directory", sddl: protectedFileSDDL, isDir: true, wantErr: "DACL entry 1 of the PMG descriptor is missing or changed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := windows.SecurityDescriptorFromString(tt.sddl)
			require.NoError(t, err)
			want, err := fileDescriptor()
			if tt.isDir {
				want, err = dirDescriptor()
			}
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

// The runtime trusts the managed config on its owner alone, so the owner
// rule is checked on descriptors built from SDDL.
func TestValidateAdministrativeControl(t *testing.T) {
	tests := []struct {
		name    string
		sddl    string
		wantErr string
	}{
		{name: "Administrators own, Users read and execute", sddl: "O:BAD:(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)"},
		{name: "SYSTEM owns, inherited entries as an MDM copy has", sddl: "O:SYD:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)"},
		{name: "a deny entry takes nothing away from the rule", sddl: "O:BAD:(D;;FW;;;BU)(A;;FA;;;BA)"},
		{name: "an inherit-only entry does not apply to the file", sddl: "O:BAD:(A;;FA;;;BA)(A;OICIIO;FW;;;BU)"},
		{name: "Users own", sddl: "O:BUD:(A;;FA;;;BA)", wantErr: "owned by BUILTIN\\Users, not by Administrators or SYSTEM"},
		{name: "a domain account owns", sddl: "O:S-1-5-21-1-2-3-1001D:(A;;FA;;;BA)", wantErr: "not by Administrators or SYSTEM"},
		{name: "no owner", sddl: "D:(A;;FA;;;BA)", wantErr: "has no owner"},
		{name: "Users may write", sddl: "O:BAD:(A;;FA;;;BA)(A;;FW;;;BU)", wantErr: "lets BUILTIN\\Users write or delete it"},
		{name: "Everyone may delete", sddl: "O:BAD:(A;;FA;;;BA)(A;;SD;;;WD)", wantErr: "lets Everyone write or delete it"},
		{name: "a domain group may change the DACL", sddl: "O:BAD:(A;;FA;;;BA)(A;;WD;;;S-1-5-21-1-2-3-1105)", wantErr: "write or delete it"},
		{name: "no DACL", sddl: "O:BA", wantErr: "has no DACL"},
		{name: "an entry PMG does not evaluate", sddl: `O:BAD:(A;;FA;;;BA)(XA;;FW;;;BU;(Member_of {SID(BA)}))`, wantErr: "does not evaluate"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tt.sddl)
			require.NoError(t, err)

			err = validateAdministrativeControl(sd, `C:\ProgramData\safedep\pmg\config.yml`)
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
	assert.ErrorContains(t, RequireSystemControlled(link), "link or a junction")
}

// A file the test created carries the temp directory's inherited descriptor,
// which is what a file a standard user dropped in looks like.
func TestRequireTrustedExistingRejectsWhatPMGDidNotWrite(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.yml")
	assert.NoError(t, RequireTrustedSystemFile(file), "a missing file passes")

	require.NoError(t, os.WriteFile(file, []byte("paranoid: false\n"), 0o644))
	assert.ErrorContains(t, RequireTrustedSystemFile(file), "does not carry the PMG security descriptor")

	assert.ErrorContains(t, RequireTrustedSystemFile(dir), "not a regular file")
}

func TestProtectRefusesWithoutElevation(t *testing.T) {
	if IsPrivileged() {
		t.Skip("the process is elevated")
	}
	file := filepath.Join(t.TempDir(), "npm.cmd")
	require.NoError(t, os.WriteFile(file, nil, 0o755))
	assert.ErrorContains(t, ProtectSystemPath(file, 0o755), "not elevated")
}

// The round trip through Windows: Protect writes the descriptor,
// RequireProtected reads it back and finds it exact, for a directory and a
// file. Then a drift is applied and repaired. Setting the owner needs
// elevation, which the CI runner has.
func TestProtectRoundTripAndRepair(t *testing.T) {
	if !IsPrivileged() {
		t.Skip("needs an elevated process")
	}
	dir := filepath.Join(t.TempDir(), "pmg")
	require.NoError(t, os.Mkdir(dir, 0o755))
	file := filepath.Join(dir, "npm.cmd")
	require.NoError(t, os.WriteFile(file, []byte("@echo off\r\n"), 0o755))
	require.Error(t, RequireProtected(dir))
	require.Error(t, RequireProtected(file))

	require.NoError(t, ProtectSystemPath(dir, 0o755))
	require.NoError(t, ProtectSystemPath(file, 0o755))
	assert.NoError(t, RequireProtected(dir))
	assert.NoError(t, RequireProtected(file))
	assert.NoError(t, RequireTrustedSystemFile(file))

	applySDDL(t, file, "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;FW;;;BU)")
	assert.ErrorContains(t, RequireProtected(file), "has 4 entries, not 3")

	require.NoError(t, ProtectSystemPath(file, 0o755))
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
