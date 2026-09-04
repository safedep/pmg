package executors

import (
	"context"
	"fmt"

	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

// newNpmExecutorCommand builds the cobra command that runs an npm-family
// package executor (npx, pnpx, aubx) through the proxy flow. track records
// the analytics event for the command.
func newNpmExecutorCommand(use, short string, track func(), config packagemanager.NpmPackageExecutorConfig) *cobra.Command {
	return &cobra.Command{
		Use:                use,
		Short:              short,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runNpmExecutorFlow(cmd.Context(), args, track, config); err != nil {
				ui.ExitFromCommandError(err)
			}

			return nil
		},
	}
}

func runNpmExecutorFlow(ctx context.Context, args []string, track func(), config packagemanager.NpmPackageExecutorConfig) error {
	track()

	packageExecutor, err := packagemanager.NewNpmPackageExecutor(config)
	if err != nil {
		return fmt.Errorf("failed to create %s package executor proxy: %w", config.CommandName, err)
	}

	return flows.RunProxy(ctx, packageExecutor, args)
}
