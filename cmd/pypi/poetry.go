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

func NewPoetryCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "poetry [action] [package]",
		Short:              "Guard poetry package manager",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executePoetryFlow(cmd.Context(), args)
			if err != nil {
				ui.ExitFromCommandError(err)
			}

			return nil
		},
	}
}

func executePoetryFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandPoetry()
	packageManager, err := packagemanager.NewPypiPackageManager(packagemanager.DefaultPoetryPackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create poetry package manager: %w", err)
	}

	return flows.RunProxy(ctx, packageManager, args)
}
