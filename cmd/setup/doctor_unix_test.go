//go:build unix

package setup

import (
	"os"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/doctor"
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
