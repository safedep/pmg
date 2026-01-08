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
	translator       *policyTranslator
	tempProfilePath  string // Path to temporary .sb file, cleaned up in Close()
	cleanupCompleted bool   // Track if cleanup already happened (idempotent Close)
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
	// The file will be cleaned up when Close() is called
	tmpFile, err := os.CreateTemp("", "pmg-sandbox-*.sb")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary sandbox profile: %w", err)
	}

	// Store the path for cleanup in Close()
	s.tempProfilePath = tmpFile.Name()

	if _, err := tmpFile.WriteString(sbProfile); err != nil {
		tmpFile.Close()
		// Clean up on error
		os.Remove(s.tempProfilePath)
		s.tempProfilePath = ""
		return nil, fmt.Errorf("failed to write sandbox profile: %w", err)
	}
	tmpFile.Close()

	log.Debugf("Seatbelt profile written to %s", s.tempProfilePath)
	log.Debugf("Seatbelt profile content:\n%s", sbProfile)

	// Modify command to run via sandbox-exec
	originalPath := cmd.Path
	originalArgs := cmd.Args

	// sandbox-exec -f <profile> <command> <args...>
	cmd.Path = "/usr/bin/sandbox-exec"
	cmd.Args = []string{
		"sandbox-exec",
		"-f", s.tempProfilePath,
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

// Close cleans up the temporary seatbelt profile file.
// Safe to call multiple times (idempotent).
func (s *seatbeltSandbox) Close() error {
	// Idempotent - return early if already cleaned up or no file to clean
	if s.cleanupCompleted || s.tempProfilePath == "" {
		return nil
	}

	log.Debugf("Cleaning up seatbelt profile: %s", s.tempProfilePath)

	err := os.Remove(s.tempProfilePath)
	s.cleanupCompleted = true

	if err != nil && !os.IsNotExist(err) {
		// Only return error if it's not "file doesn't exist"
		return fmt.Errorf("failed to remove seatbelt profile %s: %w", s.tempProfilePath, err)
	}

	return nil
}
