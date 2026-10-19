package sandbox

import (
	"github.com/safedep/pmg/config"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

// registryFactory builds a ProfileRegistry. Tests inject a stub.
type registryFactory func() (pmgsandbox.ProfileRegistry, error)

func defaultRegistryFactory() (pmgsandbox.ProfileRegistry, error) {
	// A config that failed closed holds no policy templates and no profile
	// directory, so inspection would disagree with the file the user wrote.
	if err := config.LoadError(); err != nil {
		return nil, err
	}

	// Include user presets so profile inspection agrees with runtime
	// resolution of custom profiles referencing presets.
	presets, err := defaultPresetRegistryFactory()
	if err != nil {
		return nil, err
	}

	cfg := config.Get()
	return pmgsandbox.NewProfileRegistry(
		pmgsandbox.WithUserProfileDir(cfg.SandboxProfileDir()),
		pmgsandbox.WithPresetRegistry(presets),
		pmgsandbox.WithPolicyTemplates(cfg.SandboxPolicyTemplatePaths()),
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
	cmd.AddCommand(newProfileProposeCommand(defaultRegistryFactory, defaultProposeDeps()))
	return cmd
}
