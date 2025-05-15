package npm

import (
	_ "embed"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/ui"
	"github.com/spf13/cobra"
)

func NewNpmCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "npm [action] [package]",
		Short:              "Guard npm package manager",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := config.FromContext(cmd.Context())
			if err != nil {
				ui.Fatalf("Failed to get config: %s", err)
			}

			err = executeNpmFlow(cmd.Context(), config, args)
			if err != nil {
				log.Errorf("Failed to execute npm flow: %s", err)
			}

			return nil
		},
	}
}
