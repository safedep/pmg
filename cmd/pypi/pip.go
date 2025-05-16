package pypi

import (
	"context"
	"fmt"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
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
			config, err := config.FromContext(cmd.Context())
			if err != nil {
				ui.Fatalf("Failed to get config: %s", err)
			}

			err = executePipFlow(cmd.Context(), config, args)
			if err != nil {
				log.Errorf("Failed to execute pip flow: %s", err)
			}

			return nil
		},
	}
}

func executePipFlow(context context.Context, config config.Config, args []string) error {
	packageManager, err := packagemanager.NewPipPackageManager(packagemanager.DefaultPipPackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create pip package manager: %w", err)
	}
	cmd, _ := packageManager.ParseCommand(args)
	fmt.Println("Cmd: ", cmd.InstallTargets[0])
	return nil
}
