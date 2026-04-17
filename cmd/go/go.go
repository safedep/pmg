package gocmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/ui"
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

	cmd := exec.CommandContext(ctx, "go", args...)
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
