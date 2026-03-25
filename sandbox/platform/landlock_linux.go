//go:build linux

package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox"
)

// landlockSandbox implements the Sandbox interface using Landlock LSM on Linux.
// This implementation follows the CLI-wrapper pattern (like Bubblewrap):
// - Modifies the cmd in place by rewiring it to re-exec pmg with __landlock_sandbox_exec
// - Passes the translated policy via a temp file (--policy-file)
// - Passes an audit unix socket path (--audit-socket) for future audit event consumption
// - Returns ExecutionResult with executed=false
// - Caller must call cmd.Run() to execute the sandboxed command
type landlockSandbox struct {
	abi *landlockABI

	// Cleanup state from last Execute()
	policyFile string
	socketPath string
	listener   net.Listener
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
// It closes the audit socket listener and removes temporary files.
// This method is idempotent and safe to call multiple times.
func (s *landlockSandbox) Close() error {
	if s.listener != nil {
		_ = s.listener.Close()
		s.listener = nil
	}
	if s.socketPath != "" {
		_ = os.Remove(s.socketPath)
		s.socketPath = ""
	}
	if s.policyFile != "" {
		_ = os.Remove(s.policyFile)
		s.policyFile = ""
	}
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

	// 3. Write policy JSON to a temp file
	policyFile, err := os.CreateTemp("", "pmg-landlock-policy-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create policy temp file: %w", err)
	}

	if err := json.NewEncoder(policyFile).Encode(execPolicy); err != nil {
		_ = policyFile.Close()
		_ = os.Remove(policyFile.Name())
		return nil, fmt.Errorf("failed to write policy to temp file: %w", err)
	}
	policyFilePath := policyFile.Name()
	_ = policyFile.Close()
	s.policyFile = policyFilePath

	// 4. Create unix socket for audit events
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("pmg-landlock-audit-%d.sock", os.Getpid()))
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		_ = os.Remove(policyFilePath)
		return nil, fmt.Errorf("failed to create audit unix socket: %w", err)
	}
	s.socketPath = socketPath
	s.listener = listener

	// Accept one connection and drain it (for future audit event parsing)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		io.Copy(io.Discard, conn)
		conn.Close()
	}()

	// 5. Rewire cmd to re-exec pmg with __landlock_sandbox_exec
	selfExe, err := os.Executable()
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("failed to get self executable path: %w", err)
	}

	originalPath := cmd.Path
	originalArgs := cmd.Args

	cmd.Path = selfExe
	cmd.Args = []string{
		"pmg", "__landlock_sandbox_exec",
		"--policy-file", policyFilePath,
		"--audit-socket", socketPath,
		"--", originalPath,
	}
	if len(originalArgs) > 1 {
		cmd.Args = append(cmd.Args, originalArgs[1:]...)
	}

	log.Debugf("Landlock sandboxed command: %s %v", cmd.Path, cmd.Args)

	return sandbox.NewExecutionResult(
		sandbox.WithExecutionResultExecuted(false),
		sandbox.WithExecutionResultSandbox(s),
	), nil
}
