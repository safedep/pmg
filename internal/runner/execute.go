package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/packagemanager"
	"github.com/safedep/pmg/sandbox/executor"
	"github.com/safedep/pmg/usefulerror"
)

// Execute runs a package manager command without proxy or guard analysis.
// It applies sandbox policy if configured, then executes the command directly.
func Execute(ctx context.Context, pc *packagemanager.ParsedCommand, pmName string, dryRun bool) error {
	if len(pc.Command.Exe) == 0 {
		return fmt.Errorf("no command to execute")
	}

	if dryRun {
		log.Debugf("Dry run, skipping command execution")
		return nil
	}

	cmd := exec.CommandContext(ctx, pc.Command.Exe, pc.Command.Args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	result, err := executor.ApplySandbox(ctx, cmd, pmName)
	if err != nil {
		return fmt.Errorf("failed to apply sandbox: %w", err)
	}

	defer func() {
		if err := result.Close(); err != nil {
			log.Errorf("failed to close sandbox: %v", err)
		}
	}()

	if result.ShouldRun() {
		if err := cmd.Run(); err != nil {
			humanError := "Failed to execute package manager command"
			if exitErr, ok := err.(*exec.ExitError); ok {
				humanError = fmt.Sprintf("Package manager command exited with code: %d", exitErr.ExitCode())
			}

			return usefulerror.Useful().
				WithCode(usefulerror.ErrCodePackageManagerExecutionFailed).
				WithHumanError(humanError).
				WithHelp("Check the package manager command and its arguments").
				Wrap(err)
		}
	}

	return nil
}
