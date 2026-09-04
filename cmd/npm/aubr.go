package npm

import (
	"context"
	"fmt"

	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

// NewAubrCommand guards aubr, the aube shorthand for `aube run`. A script run
// installs missing or stale dependencies first.
func NewAubrCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "aubr [script] [args]",
		Short:              "Guard aubr script runner (aube run)",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeAubrFlow(cmd.Context(), args)
			if err != nil {
				ui.ExitFromCommandError(err)
			}

			return nil
		},
	}
}

func executeAubrFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandAubr()
	packageManager, err := packagemanager.NewNpmPackageManager(packagemanager.DefaultAubrPackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create aubr package manager proxy: %w", err)
	}

	return flows.RunProxy(ctx, packageManager, args)
}
