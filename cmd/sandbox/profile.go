package sandbox

import (
	"github.com/safedep/pmg/config"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

// registryFactory builds a ProfileRegistry. Tests inject a stub.
type registryFactory func() (pmgsandbox.ProfileRegistry, error)

func defaultRegistryFactory() (pmgsandbox.ProfileRegistry, error) {
	// The preset registry must include user presets so profile inspection
	// commands (show, diff, lint) agree with runtime behavior for custom
	// profiles referencing presets under SandboxPresetDir().
	presets, err := defaultPresetRegistryFactory()
	if err != nil {
		return nil, err
	}

	return pmgsandbox.NewProfileRegistry(
		pmgsandbox.WithUserProfileDir(config.Get().SandboxProfileDir()),
		pmgsandbox.WithPresetRegistry(presets),
	)
}

// NewProfileCommand returns the `pmg sandbox profile` parent command.
func NewProfileCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Inspect sandbox profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newProfileListCommand(defaultRegistryFactory))
	cmd.AddCommand(newProfileShowCommand(defaultRegistryFactory))
	cmd.AddCommand(newProfileInitCommand(defaultRegistryFactory))
	cmd.AddCommand(newProfileEditCommand(defaultRegistryFactory))
	cmd.AddCommand(newProfileLintCommand(defaultRegistryFactory))
	cmd.AddCommand(newProfileDiffCommand(defaultRegistryFactory))
	return cmd
}
