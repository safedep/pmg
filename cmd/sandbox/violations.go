package sandbox

import (
	"github.com/safedep/pmg/config"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

// NewViolationsCommand returns the `pmg sandbox violations` parent
// command. Subcommands browse and (in future) manage the violation cache.
func NewViolationsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "violations",
		Short: "Browse and manage cached sandbox violation reports",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	factory := func() *pmgsandbox.ViolationCache {
		return pmgsandbox.NewViolationCache(config.Get().SandboxViolationCacheDir())
	}

	cmd.AddCommand(newViolationsListCommand(factory))
	return cmd
}
