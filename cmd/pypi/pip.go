package pypi

import (
	"context"
	"fmt"

	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

func NewPipCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "pip [action] [package]",
		Short:              "Guard pip package manager",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executePipFlow(cmd.Context(), args)
			if err != nil {
				ui.ExitFromCommandError(err)
			}

			return nil
		},
	}
}

func executePipFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandPip()
	packageManager, err := packagemanager.NewPypiPackageManager(packagemanager.DefaultPipPackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create pip package manager proxy: %w", err)
	}

	parsedCommand, err := packageManager.ParseCommand(args)
	if err != nil {
		return fmt.Errorf("failed to parse command: %w", err)
	}

	return flows.ProxyFlow(packageManager).Run(ctx, args, parsedCommand)
}
