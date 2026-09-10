//go:build windows

package fsutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// The ACL rules are checked on descriptors built from SDDL, so every case
// runs without elevation. BA is Administrators, SY is SYSTEM, BU is Users,
// WD is Everyone, AU is Authenticated Users, CO is CREATOR OWNER. FA is full
// access, FR read, FX execute, FW write, SD delete, LC add subdirectory,
// 0x1200a9 read and execute. A is allow, D is deny, XA is a conditional
// allow. IO marks an inherit-only entry.
func TestValidateAdminOnlyWritable(t *testing.T) {
	tests := []struct {
		name    string
		sddl    string
		wantErr string
	}{
		{
			name: "stock Program Files",
			sddl: "O:SYD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICIIO;FA;;;CO)",
		},
		{
			name: "Administrators own, Users read and execute",
			sddl: "O:BAD:(A;;FA;;;BA)(A;;0x1200a9;;;BU)",
		},
		{
			name: "a deny entry for Users is not a write",
			sddl: "O:BAD:(D;;FW;;;BU)(A;;FA;;;BA)",
		},
		{
			name:    "Users may write",
			sddl:    "O:BAD:(A;;FA;;;BA)(A;;FW;;;BU)",
			wantErr: "writable by BUILTIN\\Users",
		},
		{
			name:    "Everyone may delete",
			sddl:    "O:BAD:(A;;FA;;;BA)(A;;SD;;;WD)",
			wantErr: "writable by Everyone",
		},
		{
			name:    "Authenticated Users may write through an inherit-only entry",
			sddl:    "O:BAD:(A;;FA;;;BA)(A;OICIIO;FW;;;AU)",
			wantErr: "writable by NT AUTHORITY\\Authenticated Users",
		},
		{
			name:    "a standard user owns it",
			sddl:    "O:S-1-5-21-1-2-3-1001D:(A;;FA;;;BA)",
			wantErr: "must be owned by Administrators, SYSTEM or TrustedInstaller",
		},
		{
			name:    "no DACL is full access for everyone",
			sddl:    "O:BA",
			wantErr: "has no DACL",
		},
		{
			name:    "a conditional entry is not evaluated, so it fails",
			sddl:    `O:BAD:(A;;FA;;;BA)(XA;;FW;;;BU;(Member_of {SID(BA)}))`,
			wantErr: "which PMG does not evaluate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tt.sddl)
			require.NoError(t, err)

			err = validateAdminOnlyWritable(sd, `C:\Program Files\safedep\pmg\pmg.exe`)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// The ancestor rule: a directory a standard user can rename or delete from
// lets them replace a protected directory under it. Adding entries is fine,
// which is what the root of a volume grants every user.
func TestValidateNotReplaceable(t *testing.T) {
	tests := []struct {
		name    string
		sddl    string
		wantErr string
	}{
		{
			name: "stock volume root",
			sddl: "O:SYD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)",
		},
		{
			name: "stock ProgramData",
			sddl: "O:SYD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;LC;;;BU)(A;OICIIO;FA;;;CO)",
		},
		{
			name:    "Users may delete children",
			sddl:    "O:BAD:(A;;FA;;;BA)(A;;0x40;;;BU)",
			wantErr: "rename or delete its entries",
		},
		{
			name:    "Everyone may delete the directory",
			sddl:    "O:BAD:(A;;FA;;;BA)(A;;SD;;;WD)",
			wantErr: "rename or delete its entries",
		},
		{
			name:    "a standard user owns it",
			sddl:    "O:S-1-5-21-1-2-3-1001D:(A;;FA;;;BA)",
			wantErr: "must be owned by",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tt.sddl)
			require.NoError(t, err)

			err = validateNotReplaceable(sd, `C:\Program Files`)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestValidateExecutableByAll(t *testing.T) {
	tests := []struct {
		name    string
		sddl    string
		wantErr string
	}{
		{name: "Users read and execute", sddl: "O:BAD:(A;;FA;;;BA)(A;;0x1200a9;;;BU)"},
		{name: "Everyone execute", sddl: "O:BAD:(A;;FA;;;BA)(A;;FX;;;WD)"},
		{name: "a deny for Administrators does not matter", sddl: "O:BAD:(D;;FX;;;BA)(A;;FX;;;BU)"},
		{name: "administrators only", sddl: "O:BAD:(A;;FA;;;BA)(A;;FA;;;SY)", wantErr: "not executable by all users"},
		{name: "Users read only", sddl: "O:BAD:(A;;FA;;;BA)(A;;FR;;;BU)", wantErr: "not executable by all users"},
		{name: "inherit-only grants nothing on the file", sddl: "O:BAD:(A;;FA;;;BA)(A;OICIIO;FX;;;BU)", wantErr: "not executable by all users"},
		{name: "a deny for Users ahead of the allow", sddl: "O:BAD:(D;;FX;;;BU)(A;;FX;;;WD)", wantErr: "denies execution to BUILTIN\\Users"},
		{name: "a deny for one group after the allow", sddl: "O:BAD:(A;;FX;;;BU)(D;;FX;;;S-1-5-21-1-2-3-1105)", wantErr: "denies execution to S-1-5-21-1-2-3-1105"},
		{name: "no DACL", sddl: "O:BA", wantErr: "has no DACL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tt.sddl)
			require.NoError(t, err)

			err = validateExecutableByAll(sd, `C:\Program Files\safedep\pmg\pmg.exe`)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// Two real paths pin the rules to the operating system. cmd.exe, with every
// ancestor up to the volume root, is what a system binary must look like. A
// file in the temp directory is what a user-scope install looks like. Its
// owner is Administrators when an elevated process created it, so the
// rejection comes from the ACL or from an ancestor, whichever is first.
func TestRequireProtectedOnRealFiles(t *testing.T) {
	cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	assert.NoError(t, RequireAdminOnlyWritable(cmdExe))
	assert.NoError(t, RequireProtectedDir(filepath.Dir(cmdExe)))
	assert.NoError(t, RequireExecutableByAll(cmdExe))

	userFile := filepath.Join(t.TempDir(), "pmg.exe")
	require.NoError(t, os.WriteFile(userFile, []byte("binary"), 0o755))
	err := RequireProtectedDir(filepath.Dir(userFile))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "failed to", "the path was read, and rejected on its rights")
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
}

// RequireTrustedExisting is what stops setup from merging a config a
// standard user pre-created. A missing file passes, a user-writable file
// does not, and the same file passes once ForceRootOwned ran on it.
func TestRequireTrustedExisting(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.yml")
	assert.NoError(t, RequireTrustedExisting(file))

	require.NoError(t, os.WriteFile(file, []byte("paranoid: false\n"), 0o644))
	require.Error(t, RequireTrustedExisting(file))

	if !ProcessIsElevated() {
		t.Skip("setting the owner needs an elevated process")
	}
	require.NoError(t, ForceRootOwned(file, 0o644))
	assert.NoError(t, RequireTrustedExisting(file))
}

// ForceRootOwned is what makes a pre-created directory or an overwritten
// shim pass the checks. Setting the owner to Administrators needs
// elevation, which the CI runner has.
func TestForceRootOwnedMakesAPathAdminOnly(t *testing.T) {
	if !ProcessIsElevated() {
		t.Skip("needs an elevated process")
	}
	dir := filepath.Join(t.TempDir(), "pmg")
	require.NoError(t, os.Mkdir(dir, 0o755))
	file := filepath.Join(dir, "npm.cmd")
	require.NoError(t, os.WriteFile(file, []byte("@echo off\r\n"), 0o755))
	require.Error(t, RequireAdminOnlyWritable(file), "a file under the temp directory is user-writable")

	require.NoError(t, ForceRootOwned(dir, 0o755))
	require.NoError(t, ForceRootOwned(file, 0o755))

	// The ancestor walk is not asserted here: the temp directory sits under
	// the user's profile, which they own.
	assert.NoError(t, RequireAdminOnlyWritable(dir))
	assert.NoError(t, RequireAdminOnlyWritable(file))
	assert.NoError(t, RequireExecutableByAll(file))
}
