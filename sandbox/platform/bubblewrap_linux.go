//go:build linux
// +build linux

package platform

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox"
)

// bubblewrapSandbox implements the Sandbox interface using Bubblewrap (bwrap) on Linux.
// Bubblewrap is a low-level unprivileged sandboxing tool that uses Linux namespaces
// to isolate processes with controlled access to filesystem, network, and IPC resources.
//
// This implementation follows the CLI-wrapper pattern (like Seatbelt on macOS):
// - Modifies the cmd in place by wrapping it with `bwrap` CLI
// - Returns ExecutionResult with executed=false
// - Caller must call cmd.Run() to execute the sandboxed command
type bubblewrapSandbox struct {
	config     *bubblewrapConfig
	translator *bubblewrapPolicyTranslator
}

// newBubblewrapSandbox creates a new Bubblewrap sandbox instance with default configuration.
func newBubblewrapSandbox() (*bubblewrapSandbox, error) {
	config := newDefaultBubblewrapConfig()
	translator := newBubblewrapPolicyTranslator(config)

	return &bubblewrapSandbox{
		config:     config,
		translator: translator,
	}, nil
}

// Execute prepares a command to run in the Bubblewrap sandbox with the given policy.
// It translates the PMG policy to bwrap CLI arguments and wraps the command execution.
//
// This implementation modifies the cmd in place and does NOT execute it.
// Returns ExecutionResult with executed=false, indicating the caller must run cmd.Run().
func (b *bubblewrapSandbox) Execute(ctx context.Context, cmd *exec.Cmd, policy *sandbox.SandboxPolicy) (*sandbox.ExecutionResult, error) {
	// Translate PMG policy to bwrap arguments
	bwrapArgs, err := b.translator.translate(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to translate sandbox policy to bubblewrap arguments: %w", err)
	}

	log.Debugf("Bubblewrap arguments: %v", bwrapArgs)

	// Store original command details
	originalPath := cmd.Path
	originalArgs := cmd.Args

	// Find bwrap binary
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("bubblewrap binary not found: %w (install with: apt install bubblewrap)", err)
	}

	// Build bwrap command: bwrap [bwrap-args] -- <original-command> <original-args>
	// The "--" separator is important to distinguish bwrap args from command args
	cmd.Path = bwrapPath
	cmd.Args = []string{"bwrap"}

	// Add all translated bwrap arguments
	cmd.Args = append(cmd.Args, bwrapArgs...)

	// Add separator
	cmd.Args = append(cmd.Args, "--")

	// Add original command
	cmd.Args = append(cmd.Args, originalPath)

	// Add original arguments (skip argv[0] which is the command itself)
	if len(originalArgs) > 1 {
		cmd.Args = append(cmd.Args, originalArgs[1:]...)
	}

	log.Debugf("Sandboxed command: %s %v", cmd.Path, cmd.Args)

	// Return execution result with this sandbox instance for cleanup
	return sandbox.NewExecutionResult(sandbox.WithExecutionResultSandbox(b)), nil
}

// Name returns the name of this sandbox implementation.
func (b *bubblewrapSandbox) Name() string {
	return "bubblewrap"
}

// IsAvailable returns true if bubblewrap (bwrap) is available on this system.
// Checks by attempting to locate the bwrap binary in PATH.
func (b *bubblewrapSandbox) IsAvailable() bool {
	_, err := exec.LookPath("bwrap")
	return err == nil
}

// Close cleans up any resources allocated by the sandbox.
// For Bubblewrap, there are no temporary files to clean up (unlike Seatbelt),
// since all configuration is passed via CLI arguments.
//
// This method is idempotent and safe to call multiple times.
func (b *bubblewrapSandbox) Close() error {
	// Bubblewrap doesn't create temporary files like Seatbelt does,
	// so there's nothing to clean up. All isolation is via CLI args.
	return nil
}
