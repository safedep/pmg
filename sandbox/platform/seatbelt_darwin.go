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

type seatbeltSandbox struct {
	translator       *seatbeltPolicyTranslator
	tempProfilePath  string
	cleanupCompleted bool
}

func newSeatbeltSandbox() (*seatbeltSandbox, error) {
	return &seatbeltSandbox{
		translator: newSeatbeltPolicyTranslator(),
	}, nil
}

// Execute runs a command in the Seatbelt sandbox with the given policy.
// It translates the PMG policy to Seatbelt Profile Language (.sb) and wraps
// the command execution with sandbox-exec.
//
// This implementation modifies the cmd in place and does NOT execute it.
// Returns ExecutionResult with executed=false, indicating the caller must run cmd.Run().
func (s *seatbeltSandbox) Execute(ctx context.Context, cmd *exec.Cmd, policy *sandbox.SandboxPolicy) (*sandbox.ExecutionResult, error) {
	sbProfile, err := s.translator.translate(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to translate sandbox policy: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "pmg-sandbox-*.sb")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary sandbox profile: %w", err)
	}

	defer func() {
		if err := tmpFile.Close(); err != nil {
			log.Warnf("failed to close temporary sandbox profile: %v", err)
		}
	}()

	// Storing the path is required for cleanup in Close()
	s.tempProfilePath = tmpFile.Name()

	if _, err := tmpFile.WriteString(sbProfile); err != nil {
		if err := os.Remove(s.tempProfilePath); err != nil {
			log.Warnf("failed to remove temporary sandbox profile: %v", err)
		}

		s.tempProfilePath = ""
		return nil, fmt.Errorf("failed to write sandbox profile: %w", err)
	}

	log.Debugf("Seatbelt profile written to %s", s.tempProfilePath)

	debugLogPolicyContent(sbProfile)

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

	return sandbox.NewExecutionResult(sandbox.WithExecutionResultSandbox(s)), nil
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
func (s *seatbeltSandbox) Close() error {
	if s.cleanupCompleted || s.tempProfilePath == "" {
		return nil
	}

	log.Debugf("Cleaning up seatbelt profile: %s", s.tempProfilePath)

	err := os.Remove(s.tempProfilePath)
	s.cleanupCompleted = true

	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove seatbelt profile %s: %w", s.tempProfilePath, err)
	}

	return nil
}

// debugLogPolicyContent logs the policy content when explicitly debugging is enabled.
func debugLogPolicyContent(content string) {
	filePath := os.Getenv("PMG_SANDBOX_DEBUG_LOG_SEATBELT_POLICY_CONTENT")
	if filePath == "" {
		return
	}

	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		log.Warnf("failed to write seatbelt policy content to %s: %v", filePath, err)
	}
}
