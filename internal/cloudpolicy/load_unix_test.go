//go:build unix

package cloudpolicy

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/cloudpolicy/cloudpolicytest"
	"github.com/safedep/pmg/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheDirsUnderSudo(t *testing.T) {
	cfg := newTestConfig(t)
	invoking, err := user.Current()
	require.NoError(t, err)
	stateDir := filepath.Join(t.TempDir(), "state")
	// The test home holds no cache, so the order does not depend on the
	// caches of the host.
	home := t.TempDir()
	homeCache := filepath.Join(platform.HomeDirs(home).Config, "safedep", "pmg", "cloud-policy")
	origHome := platform.SudoUserHomeDir
	t.Cleanup(func() { platform.SudoUserHomeDir = origHome })
	platform.SudoUserHomeDir = func() (string, error) {
		if os.Getenv("SUDO_USER") == invoking.Username {
			return home, nil
		}
		return origHome()
	}

	tests := []struct {
		name       string
		privileged bool
		sudoUser   string
		stateDir   string
		want       []string
	}{
		{
			name: "a plain run reads its own cache",
			want: []string{cfg.CloudPolicyCacheDir()},
		},
		{
			name:     "SUDO_USER without privilege counts for nothing",
			sudoUser: invoking.Username,
			want:     []string{cfg.CloudPolicyCacheDir()},
		},
		{
			name:       "sudo reads the cache of the invoking user first",
			privileged: true,
			sudoUser:   invoking.Username,
			want: []string{
				homeCache,
				cfg.CloudPolicyCacheDir(),
			},
		},
		{
			name:       "sudo with PMG_STATE_DIR reads the state directory first",
			privileged: true,
			sudoUser:   invoking.Username,
			stateDir:   stateDir,
			want: []string{
				filepath.Join(stateDir, "cloud-policy"),
				homeCache,
			},
		},
		{
			name:       "an unknown sudo user reads its own cache",
			privileged: true,
			sudoUser:   "no-such-user-of-pmg",
			want:       []string{cfg.CloudPolicyCacheDir()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := platform.IsPrivileged
			t.Cleanup(func() { platform.IsPrivileged = orig })
			platform.IsPrivileged = func() bool { return tt.privileged }
			t.Setenv("SUDO_USER", tt.sudoUser)
			t.Setenv("PMG_STATE_DIR", tt.stateDir)
			config.Reload()

			assert.Equal(t, tt.want, cacheDirs(config.Get()))
		})
	}
}

func TestLoadUnderSudoAppliesTheCacheWithTheLaterFetch(t *testing.T) {
	cfg := newTestConfig(t)
	home := t.TempDir()
	homeCache := filepath.Join(platform.HomeDirs(home).Config, "safedep", "pmg", "cloud-policy")

	origPrivileged, origHome := platform.IsPrivileged, platform.SudoUserHomeDir
	t.Cleanup(func() { platform.IsPrivileged, platform.SudoUserHomeDir = origPrivileged, origHome })
	platform.IsPrivileged = func() bool { return true }
	platform.SudoUserHomeDir = func() (string, error) { return home, nil }
	t.Setenv("SUDO_USER", "runner")

	require.NoError(t, cloudpolicytest.Write(homeCache, cloudpolicytest.Policy(blockEvil()), cloudpolicytest.Header{
		Tenant:    testTenant,
		MachineID: testMachineID(t),
		Revision:  10,
	}))
	require.NoError(t, cloudpolicytest.SetFetchedAt(homeCache, time.Now().Add(-24*time.Hour)))
	writeCache(t, cfg, cloudpolicytest.Policy(blockEvil()), 11)

	st := Load(cfg, testTenant)

	require.NotNil(t, st.Applied)
	assert.Equal(t, uint64(11), st.Applied.Revision)
	assert.Equal(t, cfg.CloudPolicyCacheDir(), st.CacheDir)
}
