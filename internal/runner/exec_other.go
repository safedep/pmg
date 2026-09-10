//go:build !windows

package runner

import (
	"context"
	"os/exec"
)

func launchCommand(ctx context.Context, binary string, args []string) *exec.Cmd {
	return exec.CommandContext(ctx, binary, args...)
}

func rawCommandLine(*exec.Cmd) string { return "" }
