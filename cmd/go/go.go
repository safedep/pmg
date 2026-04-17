package gocmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/safedep/pmg/internal/analytics"
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

	cmd := exec.CommandContext(ctx, parsedCommand.Command.Exe, parsedCommand.Command.Args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}

		return fmt.Errorf("failed to execute go command: %w", err)
	}

	return nil
}
