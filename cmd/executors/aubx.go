package executors

import (
	"context"
	"fmt"

	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

// NewAubxCommand guards aubx, the aube shorthand for `aube dlx`.
func NewAubxCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "aubx [package] [action]",
		Short:              "Guard aubx package executor (aube dlx)",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeAubxFlow(cmd.Context(), args)
			if err != nil {
				ui.ExitFromCommandError(err)
			}

			return nil
		},
	}
}

func executeAubxFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandAubx()
	packageExecutor, err := packagemanager.NewNpmPackageExecutor(packagemanager.DefaultAubxPackageExecutorConfig())
	if err != nil {
		return fmt.Errorf("failed to create aubx package executor proxy: %w", err)
	}

	return flows.RunProxy(ctx, packageExecutor, args)
}
