package config

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withManagedState swaps globalConfig for a fresh one with the requested managed
// state (derived from whether the active path differs from the user path) and
// restores the original afterwards.
func withManagedState(t *testing.T, managed bool) {
	t.Helper()

	orig := globalConfig
	t.Cleanup(func() { globalConfig = orig })

	cfg := DefaultConfig()
	globalConfig = &cfg
	globalConfig.userConfigFilePath = "/user/config.yml"
	if managed {
		globalConfig.configFilePath = "/global/config.yml"
	} else {
		globalConfig.configFilePath = "/user/config.yml"
	}
}

func TestRejectManagedFlagOverrides(t *testing.T) {
	tests := []struct {
		name    string
		managed bool
		args    []string
		wantErr bool
	}{
		{"managed blocks a managed flag", true, []string{"--paranoid"}, true},
		{"managed blocks sandbox-allow", true, []string{"--sandbox-allow", "read=/tmp"}, true},
		{"managed allows dry-run", true, []string{"--dry-run"}, false},
		{"managed allows no flags", true, nil, false},
		{"unmanaged allows a managed flag", false, []string{"--paranoid"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withManagedState(t, tc.managed)

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
	withManagedState(t, true)

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
