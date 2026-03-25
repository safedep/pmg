//go:build linux

package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox"
)

// landlockSandbox implements the Sandbox interface using Landlock LSM on Linux.
// This implementation follows the CLI-wrapper pattern (like Bubblewrap):
// - Modifies the cmd in place by rewiring it to re-exec pmg with __landlock_sandbox_exec
// - Passes the translated policy via a pipe on FD=3
// - Passes an audit pipe on FD=4 for future audit event consumption
// - Returns ExecutionResult with executed=false
// - Caller must call cmd.Run() to execute the sandboxed command
type landlockSandbox struct {
	abi *landlockABI
}

// newLandlockSandbox creates a new Landlock sandbox instance after verifying
// that both Landlock and seccomp user notification are available on the system.
func newLandlockSandbox() (sandbox.Sandbox, error) {
	abi, err := landlockDetectABI()
	if err != nil {
		return nil, fmt.Errorf("landlock not available: %w", err)
	}

	log.Debugf("Landlock ABI V%d detected (Refer=%v, Truncate=%v, Network=%v, IoctlDev=%v, Scoping=%v)",
		abi.Version, abi.HasRefer, abi.HasTruncate, abi.HasNetwork, abi.HasIoctlDev, abi.HasScoping)

	log.Debugf("Probing seccomp-notify support...")
	if err := landlockProbeSeccompNotify(); err != nil {
		return nil, fmt.Errorf("seccomp-notify not available: %w", err)
	}

	log.Debugf("seccomp-notify available")

	return &landlockSandbox{abi: abi}, nil
}

// Name returns the name of this sandbox implementation.
func (s *landlockSandbox) Name() string {
	return "landlock"
}

// IsAvailable returns true if Landlock is available and functional on this system.
func (s *landlockSandbox) IsAvailable() bool {
	return s.abi != nil && s.abi.Version > 0
}

// Close cleans up any resources allocated by the sandbox.
// For Landlock, there are no persistent resources to clean up since
// all state is passed via pipes to the child process.
// This method is idempotent and safe to call multiple times.
func (s *landlockSandbox) Close() error {
	return nil
}

// Execute prepares a command to run in the Landlock sandbox with the given policy.
// It translates the PMG policy to a landlockExecPolicy, serializes it to a pipe,
// and rewires the command to re-exec pmg with the __landlock_sandbox_exec subcommand.
//
// This implementation modifies the cmd in place and does NOT execute it.
// Returns ExecutionResult with executed=false, indicating the caller must run cmd.Run().
func (s *landlockSandbox) Execute(ctx context.Context, cmd *exec.Cmd, policy *sandbox.SandboxPolicy) (*sandbox.ExecutionResult, error) {
	// 1. Translate policy -> landlockExecPolicy
	execPolicy, err := landlockTranslatePolicy(policy, s.abi)
	if err != nil {
		return nil, fmt.Errorf("failed to translate policy: %w", err)
	}

	// 2. Set target command in the exec policy
	execPolicy.Command = cmd.Path
	if len(cmd.Args) > 1 {
		execPolicy.Args = cmd.Args[1:]
	}
	execPolicy.Env = cmd.Env

	// 3. Create pipes: policy (FD=3), audit (FD=4)
	policyR, policyW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create policy pipe: %w", err)
	}

	auditR, auditW, err := os.Pipe()
	if err != nil {
		policyR.Close()
		policyW.Close()
		return nil, fmt.Errorf("failed to create audit pipe: %w", err)
	}

	// 4. Write policy JSON to pipe in goroutine
	go func() {
		defer policyW.Close()
		if encErr := json.NewEncoder(policyW).Encode(execPolicy); encErr != nil {
			log.Errorf("Failed to encode landlock exec policy: %v", encErr)
		}
	}()

	// 5. Rewire cmd to re-exec pmg with __landlock_sandbox_exec
	selfExe, err := os.Executable()
	if err != nil {
		policyR.Close()
		auditR.Close()
		auditW.Close()
		return nil, fmt.Errorf("failed to get self executable path: %w", err)
	}

	originalPath := cmd.Path
	originalArgs := cmd.Args

	cmd.Path = selfExe
	cmd.Args = []string{"pmg", "__landlock_sandbox_exec", "--", originalPath}
	if len(originalArgs) > 1 {
		cmd.Args = append(cmd.Args, originalArgs[1:]...)
	}

	// ExtraFiles must be [policyR, auditW] at indices 0 and 1,
	// mapping to FD=3 and FD=4 in the child process.
	if len(cmd.ExtraFiles) > 0 {
		// Close pipes to avoid leaking file descriptors
		policyR.Close()
		auditR.Close()
		auditW.Close()
		return nil, fmt.Errorf("cmd.ExtraFiles must be empty for landlock sandbox, got %d entries", len(cmd.ExtraFiles))
	}
	cmd.ExtraFiles = []*os.File{policyR, auditW}

	// Close auditR for now since audit consumption is out of scope.
	// In the future, this would be drained for audit events.
	auditR.Close()

	log.Debugf("Landlock sandboxed command: %s %v", cmd.Path, cmd.Args)

	return sandbox.NewExecutionResult(
		sandbox.WithExecutionResultExecuted(false),
		sandbox.WithExecutionResultSandbox(s),
	), nil
}
