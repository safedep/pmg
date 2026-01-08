package sandbox

import (
	"context"
	"os/exec"
)

// Sandbox represents a platform-specific sandbox executor that isolates
// package manager processes with controlled access to filesystem, network,
// and process execution resources.
type Sandbox interface {
	// Execute runs a command in the sandbox with the given policy.
	// The command may be modified in place (e.g., wrapped with sandbox-exec).
	// Returns an error if the sandbox setup fails.
	Execute(ctx context.Context, cmd *exec.Cmd, policy *SandboxPolicy) error

	// Name returns the sandbox implementation name (e.g., "seatbelt", "bubblewrap").
	Name() string

	// IsAvailable returns true if the sandbox is available and functional on this platform.
	IsAvailable() bool
}

// NewSandbox creates a new platform-specific sandbox instance.
// The implementation is selected at compile time using build tags.
// Returns an error if the sandbox is not available on the current platform.
func NewSandbox() (Sandbox, error) {
	return newPlatformSandbox()
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
