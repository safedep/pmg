//go:build unix

package cloudpolicy

import (
	"os/user"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheDirsUnderSudo(t *testing.T) {
	cfg := newTestConfig(t)
	invoking, err := user.Current()
	require.NoError(t, err)

	tests := []struct {
		name       string
		privileged bool
		sudoUser   string
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
				filepath.Join(platform.HomeDirs(invoking.HomeDir).Config, "safedep", "pmg", "cloud-policy"),
				cfg.CloudPolicyCacheDir(),
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

			assert.Equal(t, tt.want, cacheDirs(cfg))
		})
	}
}
