package npm

import (
	_ "embed"
	"fmt"

	"github.com/safedep/pmg/config"
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
				return fmt.Errorf("failed to get config: %w", err)
			}

			return executeNpmFlow(cmd.Context(), config, args)
		},
	}
}
