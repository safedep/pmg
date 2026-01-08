package sandbox

import (
	"context"
	"os/exec"
)

// ExecutionResult represents the result of applying a sandbox to a command.
// It encapsulates the execution state and allows for future extension with
// additional metadata (e.g., exit codes, resource usage, violation events).
// Callers must call Close() after cmd.Run() completes to clean up resources.
type ExecutionResult struct {
	executed bool
	sandbox  Sandbox // Reference to sandbox for cleanup
	// Future fields can be added here without breaking the API:
	// - exitCode int
	// - resourceUsage ResourceStats
	// - violations []ViolationEvent
}

// NewExecutionResult creates a new ExecutionResult.
// If executed is true, it indicates the sandbox executed the command directly.
// If executed is false, the sandbox only modified the command and the caller must execute it.
// The sandbox parameter can be nil if no sandbox was applied.
func NewExecutionResult(executed bool) *ExecutionResult {
	return &ExecutionResult{
		executed: executed,
		sandbox:  nil,
	}
}

// NewExecutionResultWithSandbox creates a new ExecutionResult with a sandbox reference.
// The sandbox's Close() method will be called when result.Close() is called.
func NewExecutionResultWithSandbox(executed bool, sb Sandbox) *ExecutionResult {
	return &ExecutionResult{
		executed: executed,
		sandbox:  sb,
	}
}

// WasExecuted returns true if the sandbox executed the command directly.
// If false, the caller must execute the command using cmd.Run().
func (r *ExecutionResult) WasExecuted() bool {
	return r.executed
}

// ShouldRun returns true if the caller should execute cmd.Run().
// This is the inverse of WasExecuted() and may be more intuitive at call sites.
func (r *ExecutionResult) ShouldRun() bool {
	return !r.executed
}

// Close cleans up any resources allocated by the sandbox.
// Must be called after cmd.Run() completes. Safe to call multiple times (idempotent).
// Safe to call even if no sandbox was applied (sandbox is nil).
func (r *ExecutionResult) Close() error {
	if r.sandbox != nil {
		return r.sandbox.Close()
	}
	return nil
}

// Sandbox represents a platform-specific sandbox executor that isolates
// package manager processes with controlled access to filesystem, network,
// and process execution resources.
type Sandbox interface {
	// Execute prepares or runs a command in the sandbox with the given policy.
	//
	// Behavior varies by implementation:
	// - CLI-based sandboxes (Seatbelt, Bubblewrap): Modify cmd in place by wrapping it
	//   with sandbox CLI (e.g., sandbox-exec). Returns ExecutionResult with executed=false.
	// - Library-based sandboxes: Execute the command directly within the sandbox.
	//   Returns ExecutionResult with executed=true.
	//
	// Returns:
	//   - ExecutionResult: Contains execution state and metadata
	//   - error: Non-nil if sandbox setup or execution failed
	//
	// Callers must check result.ShouldRun() and only call cmd.Run() if true.
	Execute(ctx context.Context, cmd *exec.Cmd, policy *SandboxPolicy) (*ExecutionResult, error)

	// Name returns the sandbox implementation name (e.g., "seatbelt", "bubblewrap").
	Name() string

	// IsAvailable returns true if the sandbox is available and functional on this platform.
	IsAvailable() bool

	// Close cleans up any resources allocated by the sandbox (e.g., temporary files).
	// Must be called after cmd.Run() completes. Idempotent - safe to call multiple times.
	Close() error
}


// ProfileRegistry manages built-in and custom sandbox policies.
type ProfileRegistry interface {
	// GetProfile retrieves a policy by name.
	// Name can be a built-in profile (e.g., "npm-restrictive") or a path to a custom YAML file.
	GetProfile(name string) (*SandboxPolicy, error)

	// LoadCustomProfile loads a policy from a custom YAML file path.
	LoadCustomProfile(path string) (*SandboxPolicy, error)

	// ListProfiles returns the names of all built-in profiles.
	ListProfiles() []string
}

// NewProfileRegistry creates a new profile registry with built-in policies.
func NewProfileRegistry() ProfileRegistry {
	return newDefaultProfileRegistry()
}
