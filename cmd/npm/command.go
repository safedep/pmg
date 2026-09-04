package npm

import (
	"context"
	"fmt"

	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

// newProxyCommand builds the cobra command that runs an npm-family package
// manager through the proxy flow. track records the analytics event for the
// command.
func newProxyCommand(use, short string, track func(), config packagemanager.NpmPackageManagerConfig) *cobra.Command {
	return &cobra.Command{
		Use:                use,
		Short:              short,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runProxyFlow(cmd.Context(), args, track, config); err != nil {
				ui.ExitFromCommandError(err)
			}

			return nil
		},
	}
}

func runProxyFlow(ctx context.Context, args []string, track func(), config packagemanager.NpmPackageManagerConfig) error {
	track()

	packageManager, err := packagemanager.NewNpmPackageManager(config)
	if err != nil {
		return fmt.Errorf("failed to create %s package manager proxy: %w", config.CommandName, err)
	}

	return flows.RunProxy(ctx, packageManager, args)
}
