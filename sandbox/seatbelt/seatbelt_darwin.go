//go:build darwin
// +build darwin

package seatbelt

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/safedep/dry/log"
)

// SeatbeltSandbox implements the Sandbox interface using macOS Seatbelt (sandbox-exec).
type SeatbeltSandbox struct {
	translator *PolicyTranslator
}

// NewSeatbeltSandbox creates a new Seatbelt sandbox instance.
func NewSeatbeltSandbox() (*SeatbeltSandbox, error) {
	return &SeatbeltSandbox{
		translator: NewPolicyTranslator(),
	}, nil
}

// Execute runs a command in the Seatbelt sandbox with the given policy.
// It translates the PMG policy to Seatbelt Profile Language (.sb) and wraps
// the command execution with sandbox-exec.
func (s *SeatbeltSandbox) Execute(ctx context.Context, cmd *exec.Cmd, policy *SandboxPolicy) error {
	// Translate PMG policy to Seatbelt profile
	sbProfile, err := s.translator.Translate(policy)
	if err != nil {
		return fmt.Errorf("failed to translate sandbox policy: %w", err)
	}

	// Write Seatbelt profile to temporary file
	tmpFile, err := os.CreateTemp("", "pmg-sandbox-*.sb")
	if err != nil {
		return fmt.Errorf("failed to create temporary sandbox profile: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(sbProfile); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write sandbox profile: %w", err)
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

	return nil
}

// Name returns the name of this sandbox implementation.
func (s *SeatbeltSandbox) Name() string {
	return "seatbelt"
}

// IsAvailable returns true if sandbox-exec is available on this system.
func (s *SeatbeltSandbox) IsAvailable() bool {
	_, err := exec.LookPath("sandbox-exec")
	return err == nil
}
