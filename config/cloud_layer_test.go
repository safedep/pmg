package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagedFileLockedKeys(t *testing.T) {
	keys := []string{"dependency_cooldown.enabled", "dependency_cooldown.days"}

	tests := []struct {
		name   string
		locked bool
		file   string
		want   []string
	}{
		{
			name:   "no lockdown keeps no key",
			locked: false,
			file:   "dependency_cooldown:\n  days: 14\n",
		},
		{
			name:   "lockdown keeps the key that the file sets",
			locked: true,
			file:   "global_lockdown: true\ndependency_cooldown:\n  days: 14\n",
			want:   []string{"dependency_cooldown.days"},
		},
		{
			name:   "lockdown keeps nothing that the file does not set",
			locked: true,
			file:   "global_lockdown: true\nparanoid: true\n",
		},
		{
			name:   "a section that is not a mapping sets no key",
			locked: true,
			file:   "global_lockdown: true\ndependency_cooldown: 3\n",
		},
		{
			name:   "a file that does not parse keeps every key",
			locked: true,
			file:   "global_lockdown: [\n",
			want:   keys,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			require.NoError(t, os.WriteFile(path, []byte(tt.file), 0o600))

			cfg := DefaultConfig()
			cfg.configFilePath = path
			cfg.configLocked = tt.locked

			assert.Equal(t, tt.want, cfg.ManagedFileLockedKeys(keys))
		})
	}
}

func TestRejectCloudPolicyFlagOverrides(t *testing.T) {
	cooldown := CloudKey{
		Key:      "dependency_cooldown.enabled",
		Path:     "package_admission.cooldown.min_age",
		Label:    "the dependency cooldown",
		Revision: 48,
	}

	tests := []struct {
		name      string
		cloudKeys []CloudKey
		args      []string
		wantErr   string
	}{
		{
			name:      "a flag on a key that the cloud sets fails",
			cloudKeys: []CloudKey{cooldown},
			args:      []string{"--skip-dependency-cooldown"},
			wantErr:   "--skip-dependency-cooldown is not allowed. The policy of your tenant sets the dependency cooldown (package_admission.cooldown.min_age, policy revision 48)",
		},
		{
			name:      "a flag on another key passes",
			cloudKeys: []CloudKey{cooldown},
			args:      []string{"--paranoid"},
		},
		{
			name: "the flag passes when the cloud does not set the key",
			args: []string{"--skip-dependency-cooldown"},
		},
		{
			name:      "no flag passes",
			cloudKeys: []CloudKey{cooldown},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withLockedState(t, false)
			Get().SetCloudKeys(tt.cloudKeys)

			cmd := &cobra.Command{Use: "test", Run: func(*cobra.Command, []string) {}}
			ApplyCobraFlags(cmd)
			t.Cleanup(func() { skipDependencyCooldown = false })
			require.NoError(t, cmd.ParseFlags(tt.args))

			err := RejectCloudPolicyFlagOverrides(cmd)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			usefulErr, ok := usefulerror.AsUsefulError(err)
			require.True(t, ok)
			assert.Equal(t, errcodes.InvalidArgument, usefulErr.Code())
			assert.Equal(t, tt.wantErr, usefulErr.HumanError())
		})
	}
}
