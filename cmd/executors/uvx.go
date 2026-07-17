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

func NewUvxCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "uvx [package] [args]",
		Short:              "Guard uvx package executor",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeUvxFlow(cmd.Context(), args)
			if err != nil {
				ui.ExitFromCommandError(err)
			}

			return nil
		},
	}
}

func executeUvxFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandUvx()

	packageExecutor, err := packagemanager.NewPypiPackageExecutor(packagemanager.DefaultUvxPackageExecutorConfig())
	if err != nil {
		return fmt.Errorf("failed to create uvx package executor proxy: %w", err)
	}

	return flows.RunProxy(ctx, packageExecutor, args)
}
