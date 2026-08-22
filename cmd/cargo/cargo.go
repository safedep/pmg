package cargo

import (
	"context"
	"fmt"

	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

func NewCargoCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "cargo [action] [crate]",
		Short:              "Guard cargo crate downloads (experimental)",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeCargoFlow(cmd.Context(), args)
			if err != nil {
				ui.ExitFromCommandError(err)
			}

			return nil
		},
	}
}

func executeCargoFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandCargo()

	packageManager, err := packagemanager.NewCargoPackageManager(packagemanager.DefaultCargoPackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create cargo package manager: %w", err)
	}

	return flows.RunProxy(ctx, packageManager, args)
}
