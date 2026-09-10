//go:build windows

package shim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safedep/pmg/internal/fsutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// The ACL rules are checked on descriptors built from SDDL, so every case
// runs without elevation. BA is Administrators, SY is SYSTEM, BU is Users,
// WD is Everyone, AU is Authenticated Users, CO is CREATOR OWNER. FA is full
// access, FR read, FX execute, FW write, SD delete, LC add subdirectory,
// 0x1200a9 read and execute. A is allow, D is deny. IO marks an inherit-only
// entry.
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
		{name: "administrators only", sddl: "O:BAD:(A;;FA;;;BA)(A;;FA;;;SY)", wantErr: "not executable by all users"},
		{name: "Users read only", sddl: "O:BAD:(A;;FA;;;BA)(A;;FR;;;BU)", wantErr: "not executable by all users"},
		{name: "inherit-only grants nothing on the file", sddl: "O:BAD:(A;;FA;;;BA)(A;OICIIO;FX;;;BU)", wantErr: "not executable by all users"},
		{name: "a deny ahead of the allow wins", sddl: "O:BAD:(D;;FX;;;BU)(A;;FX;;;WD)", wantErr: "denies execution to BUILTIN\\Users"},
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
func TestValidateSystemExecutableOnRealFiles(t *testing.T) {
	cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	assert.NoError(t, validateSystemExecutable(cmdExe))

	userFile := filepath.Join(t.TempDir(), "pmg.exe")
	require.NoError(t, os.WriteFile(userFile, []byte("binary"), 0o755))
	err := validateSystemExecutable(userFile)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "failed to", "the file was read, and rejected on its rights")
}

// ForceRootOwned is what makes a pre-created directory or an overwritten
// shim pass the checks. Setting the owner to Administrators needs
// elevation, which the CI runner has.
func TestForceRootOwnedMakesAPathAdminOnly(t *testing.T) {
	if !fsutil.ProcessIsElevated() {
		t.Skip("needs an elevated process")
	}
	dir := filepath.Join(t.TempDir(), "pmg")
	require.NoError(t, os.Mkdir(dir, 0o755))
	file := filepath.Join(dir, "npm.cmd")
	require.NoError(t, os.WriteFile(file, []byte("@echo off\r\n"), 0o755))
	require.Error(t, requireAdminOnlyWritable(file), "a file under the temp directory is user-writable")

	require.NoError(t, fsutil.ForceRootOwned(dir, 0o755))
	require.NoError(t, fsutil.ForceRootOwned(file, 0o755))

	// The ancestor walk is not asserted here: the temp directory sits under
	// the user's profile, which they own.
	assert.NoError(t, requireAdminOnlyWritable(dir))
	assert.NoError(t, requireAdminOnlyWritable(file))
	assert.NoError(t, requireExecutableByAll(file))
}

func TestMachinePathRegistry(t *testing.T) {
	isolateMachinePath(t)
	shimDir := `C:\Program Files\safedep\pmg\bin`

	t.Run("registers first and keeps the value type", func(t *testing.T) {
		setRegistryPath(t, machineEnvironmentRoot, machineEnvironmentKey,
			`%SystemRoot%\system32;C:\Program Files\nodejs\`)

		require.NoError(t, registerMachinePath(shimDir))
		require.NoError(t, registerMachinePath(shimDir))

		entries, expand, err := readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
		require.NoError(t, err)
		assert.Equal(t, []string{shimDir, `%SystemRoot%\system32`, `C:\Program Files\nodejs\`}, entries)
		assert.True(t, expand)
	})

	t.Run("moves the directory back to the front", func(t *testing.T) {
		require.NoError(t, writeRawPath(machineEnvironmentRoot, machineEnvironmentKey,
			[]string{`C:\Program Files\nodejs\`, shimDir + `\`}, true))

		require.NoError(t, registerMachinePath(shimDir))

		entries, _, err := readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
		require.NoError(t, err)
		assert.Equal(t, []string{shimDir, `C:\Program Files\nodejs\`}, entries)
	})

	t.Run("an entry written through a variable counts as present", func(t *testing.T) {
		require.NoError(t, writeRawPath(machineEnvironmentRoot, machineEnvironmentKey,
			[]string{`%ProgramFiles%\safedep\pmg\bin`, `C:\Tools`}, true))

		found, err := machinePathContains(filepath.Join(os.Getenv("ProgramFiles"), `safedep\pmg\bin`))
		require.NoError(t, err)
		assert.True(t, found)
	})

	t.Run("append adds once at the end and moves nothing", func(t *testing.T) {
		require.NoError(t, writeRawPath(machineEnvironmentRoot, machineEnvironmentKey,
			[]string{shimDir, `C:\Tools`}, true))

		require.NoError(t, appendMachinePath(`C:\Program Files\safedep\pmg`))
		require.NoError(t, appendMachinePath(`C:\Program Files\safedep\pmg`))
		require.NoError(t, appendMachinePath(`c:\tools`))

		entries, _, err := readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
		require.NoError(t, err)
		assert.Equal(t, []string{shimDir, `C:\Tools`, `C:\Program Files\safedep\pmg`}, entries)
	})

	t.Run("unregister removes only the directory and never the value", func(t *testing.T) {
		require.NoError(t, writeRawPath(machineEnvironmentRoot, machineEnvironmentKey,
			[]string{shimDir, `C:\Tools`}, false))

		require.NoError(t, unregisterMachinePath(strings.ToLower(shimDir)))
		require.NoError(t, unregisterMachinePath(shimDir))

		entries, expand, err := readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
		require.NoError(t, err)
		assert.Equal(t, []string{`C:\Tools`}, entries)
		assert.False(t, expand, "a REG_SZ value stays REG_SZ")

		require.NoError(t, unregisterMachinePath(`C:\Tools`))
		entries, _, err = readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
		require.NoError(t, err)
		assert.Empty(t, entries)
	})
}

// useSystemPaths is the Windows twin of the Unix helper. The temp directory
// is user-owned, so the ACL checks are off and covered by their own tests.
func useSystemPaths(t *testing.T, dir string) {
	t.Helper()
	isolateMachinePath(t)
	systemBinDirOverride = filepath.Join(dir, "bin")
	systemExecutableOwnershipCheck = false

	exe := filepath.Join(dir, "pmg.exe")
	require.NoError(t, os.WriteFile(exe, []byte("binary"), 0o755))
	resolveExecutable = func() (string, error) { return exe, nil }

	t.Cleanup(func() {
		systemBinDirOverride = ""
		systemExecutableOwnershipCheck = true
		resolveExecutable = currentExecutable
	})
}

func TestSystemShimManagerInstallAndRemove(t *testing.T) {
	root := t.TempDir()
	useSystemPaths(t, root)
	setRegistryPath(t, machineEnvironmentRoot, machineEnvironmentKey, `C:\Program Files\nodejs\`)

	mgr, err := NewSystemShimManager()
	require.NoError(t, err)
	assert.True(t, mgr.config.SkipUserPath)
	assert.True(t, mgr.config.SystemProfile)
	assert.Equal(t, "", SystemProfilePath())

	require.NoError(t, mgr.Install())
	assert.True(t, SystemShimsInstalled())
	assert.True(t, SystemPathInstalled())

	entries, _, err := readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
	require.NoError(t, err)
	assert.Equal(t, []string{SystemBinDir(), `C:\Program Files\nodejs\`, root}, entries,
		"the shim directory goes first and the binary's directory last, so `pmg` itself resolves")

	content, err := os.ReadFile(filepath.Join(SystemBinDir(), "npm.cmd"))
	require.NoError(t, err)
	assert.Contains(t, string(content), filepath.Join(root, "pmg.exe"))

	bin, ok := SystemShimBinary()
	require.True(t, ok)
	assert.Equal(t, filepath.Join(root, "pmg.exe"), bin)

	// A second install is a no-op on the PATH and rewrites the shims.
	require.NoError(t, mgr.Install())
	entries, _, err = readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
	require.NoError(t, err)
	assert.Equal(t, []string{SystemBinDir(), `C:\Program Files\nodejs\`, root}, entries)

	require.NoError(t, mgr.Remove())
	assert.False(t, SystemShimsInstalled())
	assert.False(t, SystemPathInstalled())
	require.NoError(t, mgr.Remove())

	entries, _, err = readRawPath(machineEnvironmentRoot, machineEnvironmentKey)
	require.NoError(t, err)
	assert.Equal(t, []string{`C:\Program Files\nodejs\`, root}, entries, "the binary stays, so its directory stays on PATH")
}

// With the checks on, an elevated install into the temp directory writes
// administrator-only shims and passes its own validation. This is the path
// a real install takes.
func TestSystemShimManagerInstallForcesAdminOnlyShims(t *testing.T) {
	if !fsutil.ProcessIsElevated() {
		t.Skip("needs an elevated process")
	}
	root := t.TempDir()
	useSystemPaths(t, root)
	systemExecutableOwnershipCheck = true
	setRegistryPath(t, machineEnvironmentRoot, machineEnvironmentKey, `C:\Tools`)

	// The temp binary cannot pass the executable check, so the manager is
	// built with the check off and the shim checks run on their own.
	systemExecutableOwnershipCheck = false
	mgr, err := NewSystemShimManager()
	require.NoError(t, err)
	require.NoError(t, mgr.Install())

	// Not validateSystemShimDir: its ancestor walk reaches the user's
	// profile, which they own. The directory and every shim are checked.
	assert.NoError(t, requireAdminOnlyWritable(SystemBinDir()))
	entries, err := os.ReadDir(SystemBinDir())
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	for _, entry := range entries {
		assert.NoError(t, requireAdminOnlyWritable(filepath.Join(SystemBinDir(), entry.Name())), entry.Name())
	}
}

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
