package gocmd

import (
	"context"
	"fmt"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

func NewGoCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "go [action] [package]",
		Short:              "Run go through PMG",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeGoFlow(cmd.Context(), args)
			if err != nil {
				ui.ErrorExit(err)
			}

			return nil
		},
	}
}

func executeGoFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandGo()

	packageManager, err := packagemanager.NewGoPackageManager(packagemanager.DefaultGoPackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create go package manager: %w", err)
	}

	parsedCommand, err := packageManager.ParseCommand(args)
	if err != nil {
		return fmt.Errorf("failed to parse command: %w", err)
	}

	packageResolver, err := packagemanager.NewGoDependencyResolver(packagemanager.NewDefaultGoDependencyResolverConfig())
	if err != nil {
		return fmt.Errorf("failed to create dependency resolver: %w", err)
	}

	if config.Get().IsProxyModeEnabled() {
		return flows.ProxyFlow(packageManager, packageResolver).Run(ctx, args, parsedCommand)
	}

	return flows.Common(packageManager, packageResolver).Run(ctx, args, parsedCommand)
}
