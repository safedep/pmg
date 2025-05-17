package npm

import (
	"context"
	_ "embed"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

func NewNpmCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "npm [action] [package]",
		Short:              "Guard npm package manager",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeNpmFlow(cmd.Context(), args)
			if err != nil {
				log.Errorf("Failed to execute npm flow: %s", err)
			}

			return nil
		},
	}
}

func executeNpmFlow(ctx context.Context, args []string) error {
	packageManager, err := packagemanager.NewNpmPackageManager(packagemanager.DefaultNpmPackageManagerConfig())
	if err != nil {
		ui.Fatalf("Failed to create npm package manager proxy: %s", err)
	}

	return flows.Common(packageManager).Run(ctx, args)
}
