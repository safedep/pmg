package sandbox

import (
	"fmt"
	"strings"
)

// SandboxPolicy represents a parsed and validated sandbox policy that defines
// filesystem, network, and process execution restrictions for package managers.
// Policy violations will block execution.
type SandboxPolicy struct {
	Name            string           `yaml:"name" json:"name"`
	Description     string           `yaml:"description" json:"description"`
	Inherits        string           `yaml:"inherits,omitempty" json:"inherits,omitempty"` // Optional parent profile name
	PackageManagers []string         `yaml:"package_managers" json:"package_managers"`
	Filesystem      FilesystemPolicy `yaml:"filesystem" json:"filesystem"`
	Network         NetworkPolicy    `yaml:"network" json:"network"`
	Process         ProcessPolicy    `yaml:"process" json:"process"`

	// AllowGitConfig allows write access to .git/config file.
	AllowGitConfig bool `yaml:"allow_git_config" json:"allow_git_config"`
	// AllowPTY allows pseudo-terminal (PTY) operations.
	AllowPTY bool `yaml:"allow_pty" json:"allow_pty"`
}

// FilesystemPolicy defines allowed and denied filesystem access patterns.
// Deny rules have higher priority than allow rules.
type FilesystemPolicy struct {
	AllowRead  []string `yaml:"allow_read" json:"allow_read"`
	AllowWrite []string `yaml:"allow_write" json:"allow_write"`
	DenyRead   []string `yaml:"deny_read" json:"deny_read"`
	DenyWrite  []string `yaml:"deny_write" json:"deny_write"`
}

// NetworkPolicy defines allowed and denied network access patterns.
// Patterns are in the format "host:port" or "*:*" for wildcards.
type NetworkPolicy struct {
	AllowOutbound []string `yaml:"allow_outbound" json:"allow_outbound"`
	DenyOutbound  []string `yaml:"deny_outbound" json:"deny_outbound"`
}

// ProcessPolicy defines allowed and denied process execution patterns.
// Patterns can be specific paths or glob patterns.
type ProcessPolicy struct {
	AllowExec []string `yaml:"allow_exec" json:"allow_exec"`
	DenyExec  []string `yaml:"deny_exec" json:"deny_exec"`
}

// Validate validates the sandbox policy for correctness before inheritance resolution.
// Returns an error if the policy is invalid.
// Note: Validation for "at least one rule" check is deferred to ValidateResolved(),
// since a child policy might have no rules of its own but inherit rules from its parent.
func (p *SandboxPolicy) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("policy name is required")
	}

	if len(p.PackageManagers) == 0 {
		return fmt.Errorf("policy must specify at least one package manager")
	}

	return nil
}

// ValidateResolved validates a policy after inheritance has been resolved.
// This is called after MergeWithParent to ensure the final policy is valid.
func (p *SandboxPolicy) ValidateResolved() error {
	if err := p.Validate(); err != nil {
		return err
	}

	// Check that at least one access rule is defined (after inheritance)
	hasRules := len(p.Filesystem.AllowRead) > 0 ||
		len(p.Filesystem.AllowWrite) > 0 ||
		len(p.Filesystem.DenyRead) > 0 ||
		len(p.Filesystem.DenyWrite) > 0 ||
		len(p.Network.AllowOutbound) > 0 ||
		len(p.Network.DenyOutbound) > 0 ||
		len(p.Process.AllowExec) > 0 ||
		len(p.Process.DenyExec) > 0

	if !hasRules {
		return fmt.Errorf("policy must define at least one access rule (after inheritance resolution)")
	}

	return nil
}

// AppliesToPackageManager returns true if this policy applies to the given package manager.
func (p *SandboxPolicy) AppliesToPackageManager(pm string) bool {
	pmLower := strings.ToLower(pm)
	for _, supported := range p.PackageManagers {
		if strings.ToLower(supported) == pmLower {
			return true
		}
	}

	return false
}

// MergeWithParent merges the child policy with its parent policy.
// Lists are unioned (additive), package_managers are replaced, booleans are overridden.
// This method modifies the receiver (child policy) in place.
func (child *SandboxPolicy) MergeWithParent(parent *SandboxPolicy) {
	// Union filesystem lists
	child.Filesystem.AllowRead = unionStringSlices(parent.Filesystem.AllowRead, child.Filesystem.AllowRead)
	child.Filesystem.AllowWrite = unionStringSlices(parent.Filesystem.AllowWrite, child.Filesystem.AllowWrite)
	child.Filesystem.DenyRead = unionStringSlices(parent.Filesystem.DenyRead, child.Filesystem.DenyRead)
	child.Filesystem.DenyWrite = unionStringSlices(parent.Filesystem.DenyWrite, child.Filesystem.DenyWrite)

	// Union network lists
	child.Network.AllowOutbound = unionStringSlices(parent.Network.AllowOutbound, child.Network.AllowOutbound)
	child.Network.DenyOutbound = unionStringSlices(parent.Network.DenyOutbound, child.Network.DenyOutbound)

	// Union process lists
	child.Process.AllowExec = unionStringSlices(parent.Process.AllowExec, child.Process.AllowExec)
	child.Process.DenyExec = unionStringSlices(parent.Process.DenyExec, child.Process.DenyExec)
}

// unionStringSlices returns a new slice containing all unique elements from both slices.
// Order is preserved: parent entries first, then child entries (excluding duplicates).
func unionStringSlices(parent, child []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(parent)+len(child))

	// Add all parent entries
	for _, item := range parent {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	// Add child entries that aren't duplicates
	for _, item := range child {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}
