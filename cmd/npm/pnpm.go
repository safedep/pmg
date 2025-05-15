package npm

import (
	_ "embed"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/ui"
	"github.com/spf13/cobra"
)

func NewPnpmCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "pnpm [action] [package]",
		Short:              "Guard pnpm package manager",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := config.FromContext(cmd.Context())
			if err != nil {
				ui.Fatalf("Failed to get config: %s", err)
			}

			err = executePnpmFlow(cmd.Context(), config, args)
			if err != nil {
				ui.Fatalf("Failed to execute pnpm flow: %s", err)
			}

			return nil
		},
	}
}
