//go:build unix

package setup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/doctor"
	"github.com/safedep/pmg/internal/platform/platformtest"
	"github.com/safedep/pmg/internal/shim"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Windows fix text does not apply off Windows, so the doctor table keeps
// its usual hint for a shadowed manager.
func TestShadowedFixIsEmptyOffWindows(t *testing.T) {
	assert.Equal(t, "", shadowedFix([]shim.ManagerResolution{{Name: "npm", Path: "/usr/bin/npm"}}))
}

// os.Chmod cannot make a directory unwritable on Windows, so the probe
// succeeds there and the failure path never runs.
func TestCheckEventLogDirResultUnwritable(t *testing.T) {
	configDir := "/home/dev/.config/safedep/pmg"
	if os.Geteuid() == 0 {
		t.Skip("running as root: directory permissions are not enforced")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() {
		require.NoError(t, os.Chmod(dir, 0o755))
	})

	result := checkEventLogDirResult(false, dir, configDir)
	assert.Equal(t, doctor.StatusFail, result.Status)
	assert.Equal(t, "Event log directory not writable", result.Message)
	_, expectedFix := config.UnwritableConfigDirRemedy(configDir)
	assert.Equal(t, expectedFix, result.Fix)
}

// A managed config that PMG ignores drops global_lockdown on the machine,
// so its doctor row fails with the reason and the remedy.
func TestCheckManagedConfigResult(t *testing.T) {
	tests := []struct {
		name       string
		fileMode   os.FileMode
		wantStatus doctor.CheckStatus
		wantText   string
		wantFix    string
	}{
		{name: "only the system account can change it", fileMode: 0o644, wantStatus: doctor.StatusPass, wantText: "Only the system account can change the managed config"},
		{name: "the group may write it", fileMode: 0o664, wantStatus: doctor.StatusFail, wantText: "config.yml lets its group write it", wantFix: "sudo chmod go-w"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "safedep", "pmg")
			require.NoError(t, os.MkdirAll(dir, 0o755))
			require.NoError(t, os.Chmod(filepath.Dir(dir), 0o755))
			require.NoError(t, os.Chmod(dir, 0o755))
			path := filepath.Join(dir, "config.yml")
			require.NoError(t, os.WriteFile(path, []byte("global_lockdown: true\n"), 0o644))
			require.NoError(t, os.Chmod(path, tc.fileMode))
			t.Setenv("PMG_CONFIG_DIR", t.TempDir())
			platformtest.TrustCurrentUser(t)
			t.Cleanup(config.SetManagedConfigDirForTest(dir))

			result := checkManagedConfigResult(config.Get())
			assert.Equal(t, tc.wantStatus, result.Status)
			assert.Contains(t, result.Message, tc.wantText)
			assert.Contains(t, result.Fix, tc.wantFix)
		})
	}
}
