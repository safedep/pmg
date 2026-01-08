//go:build darwin
// +build darwin

package platform

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox"
)

// seatbeltSandbox implements the Sandbox interface using macOS Seatbelt (sandbox-exec).
type seatbeltSandbox struct {
	translator *policyTranslator
}

// newSeatbeltSandbox creates a new Seatbelt sandbox instance.
func newSeatbeltSandbox() (*seatbeltSandbox, error) {
	return &seatbeltSandbox{
		translator: newPolicyTranslator(),
	}, nil
}

// Execute runs a command in the Seatbelt sandbox with the given policy.
// It translates the PMG policy to Seatbelt Profile Language (.sb) and wraps
// the command execution with sandbox-exec.
//
// This implementation modifies the cmd in place and does NOT execute it.
// Returns ExecutionResult with executed=false, indicating the caller must run cmd.Run().
func (s *seatbeltSandbox) Execute(ctx context.Context, cmd *exec.Cmd, policy *sandbox.SandboxPolicy) (*sandbox.ExecutionResult, error) {
	// Translate PMG policy to Seatbelt profile
	sbProfile, err := s.translator.translate(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to translate sandbox policy: %w", err)
	}

	// Write Seatbelt profile to temporary file
	tmpFile, err := os.CreateTemp("", "pmg-sandbox-*.sb")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary sandbox profile: %w", err)
	}

	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(sbProfile); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("failed to write sandbox profile: %w", err)
	}
	tmpFile.Close()

	log.Debugf("Seatbelt profile written to %s", tmpFile.Name())
	log.Debugf("Seatbelt profile content:\n%s", sbProfile)

	// Modify command to run via sandbox-exec
	originalPath := cmd.Path
	originalArgs := cmd.Args

	// sandbox-exec -f <profile> <command> <args...>
	cmd.Path = "/usr/bin/sandbox-exec"
	cmd.Args = []string{
		"sandbox-exec",
		"-f", tmpFile.Name(),
		originalPath,
	}

	// Append original arguments (skip argv[0] which is the command itself)
	if len(originalArgs) > 1 {
		cmd.Args = append(cmd.Args, originalArgs[1:]...)
	}

	log.Debugf("Sandboxed command: %s %v", cmd.Path, cmd.Args)

	// Return ExecutionResult indicating we only modified cmd, didn't execute it
	return sandbox.NewExecutionResult(false), nil
}

// Name returns the name of this sandbox implementation.
func (s *seatbeltSandbox) Name() string {
	return "seatbelt"
}

// IsAvailable returns true if sandbox-exec is available on this system.
func (s *seatbeltSandbox) IsAvailable() bool {
	_, err := exec.LookPath("sandbox-exec")
	return err == nil
}
