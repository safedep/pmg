package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/shim"
	"github.com/safedep/pmg/packagemanager"
	"github.com/safedep/pmg/sandbox/executor"
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

	realBinary, err := shim.ResolveRealBinary(pc.Command.Exe)
	if err != nil {
		return fmt.Errorf("failed to resolve real %s binary: %w", pc.Command.Exe, err)
	}

	cmd := exec.CommandContext(ctx, realBinary, pc.Command.Args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = shim.FilterPMGFromEnv(os.Environ())

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
			exitCode := -1
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			}
			return executor.WrapCommandExecutionError(err, result, exitCode)
		}
	}

	return nil
}
