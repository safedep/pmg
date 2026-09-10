//go:build windows

package shim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// The ACL rules are checked on descriptors built from SDDL, so every case
// runs without elevation. BA is Administrators, SY is SYSTEM, BU is Users,
// WD is Everyone, AU is Authenticated Users, CO is CREATOR OWNER. FA is full
// access, FR read, FX execute, FW write. The trailing "IO" flag marks an
// inherit-only entry.
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

func TestValidateExecutableByAll(t *testing.T) {
	tests := []struct {
		name string
		sddl string
		ok   bool
	}{
		{name: "Users read and execute", sddl: "O:BAD:(A;;FA;;;BA)(A;;0x1200a9;;;BU)", ok: true},
		{name: "Everyone execute", sddl: "O:BAD:(A;;FA;;;BA)(A;;FX;;;WD)", ok: true},
		{name: "administrators only", sddl: "O:BAD:(A;;FA;;;BA)(A;;FA;;;SY)"},
		{name: "Users read only", sddl: "O:BAD:(A;;FA;;;BA)(A;;FR;;;BU)"},
		{name: "inherit-only grants nothing on the file", sddl: "O:BAD:(A;;FA;;;BA)(A;OICIIO;FX;;;BU)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tt.sddl)
			require.NoError(t, err)

			err = validateExecutableByAll(sd, `C:\Program Files\safedep\pmg\pmg.exe`)
			if tt.ok {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, "not executable by all users")
		})
	}
}

// Two real files pin the rules to the operating system. cmd.exe is what a
// system binary must look like. A file in the temp directory is what a
// user-scope install looks like, and it must be rejected.
func TestValidateSystemExecutableOnRealFiles(t *testing.T) {
	cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	assert.NoError(t, validateSystemExecutable(cmdExe))

	userFile := filepath.Join(t.TempDir(), "pmg.exe")
	require.NoError(t, os.WriteFile(userFile, []byte("binary"), 0o755))
	err := validateSystemExecutable(userFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be owned by")
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
	assert.Equal(t, []string{SystemBinDir(), `C:\Program Files\nodejs\`}, entries, "the shim directory goes first")

	content, err := os.ReadFile(filepath.Join(SystemBinDir(), "npm.cmd"))
	require.NoError(t, err)
	assert.Contains(t, string(content), filepath.Join(root, "pmg.exe"))

	bin, ok := SystemShimBinary()
	require.True(t, ok)
	assert.Equal(t, filepath.Join(root, "pmg.exe"), bin)

	require.NoError(t, mgr.Remove())
	assert.False(t, SystemShimsInstalled())
	assert.False(t, SystemPathInstalled())
	require.NoError(t, mgr.Remove())
}

func TestDefaultSystemBinDirUnderProgramFiles(t *testing.T) {
	t.Setenv("ProgramFiles", `D:\Programs`)
	assert.Equal(t, `D:\Programs\safedep\pmg\bin`, defaultSystemBinDir())
}
