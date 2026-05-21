package config

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withLockedState swaps globalConfig for a fresh managed config with the
// requested lockdown state, and restores the original afterwards. Locked implies
// managed, matching production (initConfig sets configLocked = IsManaged() && ...).
func withLockedState(t *testing.T, locked bool) {
	t.Helper()

	orig := globalConfig
	t.Cleanup(func() { globalConfig = orig })

	cfg := DefaultConfig()
	globalConfig = &cfg
	globalConfig.configFilePath = "/global/config.yml" // managed: active path differs from user path
	globalConfig.userConfigFilePath = "/user/config.yml"
	globalConfig.configLocked = locked
}

func TestRejectManagedFlagOverrides(t *testing.T) {
	tests := []struct {
		name    string
		locked  bool
		args    []string
		wantErr bool
	}{
		{"locked blocks a managed flag", true, []string{"--paranoid"}, true},
		{"locked blocks sandbox-allow", true, []string{"--sandbox-allow", "read=/tmp"}, true},
		{"locked allows dry-run", true, []string{"--dry-run"}, false},
		{"locked allows no flags", true, nil, false},
		{"unlocked allows a managed flag", false, []string{"--paranoid"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withLockedState(t, tc.locked)

			cmd := &cobra.Command{Use: "test", Run: func(*cobra.Command, []string) {}}
			ApplyCobraFlags(cmd)
			require.NoError(t, cmd.ParseFlags(tc.args))

			err := RejectManagedFlagOverrides(cmd)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "globally managed")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Proves the check sees managed flags set as inherited persistent flags on a
// subcommand, which is how they reach the real root PersistentPreRun.
func TestRejectManagedFlagOverridesDetectsInheritedFlag(t *testing.T) {
	withLockedState(t, true)

	root := &cobra.Command{Use: "pmg"}
	ApplyCobraFlags(root)

	var checked bool
	child := &cobra.Command{
		Use: "install",
		RunE: func(cmd *cobra.Command, _ []string) error {
			checked = true
			return RejectManagedFlagOverrides(cmd)
		},
	}
	root.AddCommand(child)
	root.SetArgs([]string{"install", "--sandbox=false"})

	err := root.Execute()
	require.True(t, checked)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "globally managed")
}

// Proves the SSOT table is internally consistent: every spec actually binds a
// flag, every registered flag traces back to a spec (no out-of-band flags), and
// the managed classification matches intent. Catches accidental managed flips
// and config flags added without classification.
func TestConfigFlagSpecsSSOT(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	ApplyCobraFlags(cmd)

	specByName := make(map[string]flagSpec, len(configFlagSpecs))
	gotManaged := make(map[string]bool)
	for _, f := range configFlagSpecs {
		specByName[f.name] = f
		require.NotNil(t, cmd.PersistentFlags().Lookup(f.name), "spec %q is not registered by ApplyCobraFlags", f.name)
		if f.managed {
			gotManaged[f.name] = true
		}
	}

	// No flag is registered outside the SSOT table.
	cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		_, ok := specByName[f.Name]
		assert.True(t, ok, "flag --%s is registered but has no flagSpec", f.Name)
	})

	wantManaged := map[string]bool{
		"transitive": true, "transitive-depth": true, "include-dev-dependencies": true,
		"paranoid": true, "skip-event-log": true, "proxy-mode": true,
		"sandbox": true, "sandbox-enforce": true, "sandbox-profile": true,
		"sandbox-allow": true, "skip-dependency-cooldown": true,
	}
	assert.Equal(t, wantManaged, gotManaged, "managed flag classification changed unexpectedly")
}
