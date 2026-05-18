package sandbox

import (
	"github.com/safedep/pmg/config"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

// registryFactory builds a ProfileRegistry. Tests inject a stub.
type registryFactory func() (pmgsandbox.ProfileRegistry, error)

func defaultRegistryFactory() (pmgsandbox.ProfileRegistry, error) {
	return pmgsandbox.NewProfileRegistry(
		pmgsandbox.WithUserProfileDir(config.Get().SandboxProfileDir()),
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
	cmd.AddCommand(newProfileLintCommand(defaultRegistryFactory))
	cmd.AddCommand(newProfileDiffCommand(defaultRegistryFactory))
	return cmd
}
