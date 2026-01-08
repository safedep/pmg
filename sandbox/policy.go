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
	PackageManagers []string         `yaml:"package_managers" json:"package_managers"`
	Filesystem      FilesystemPolicy `yaml:"filesystem" json:"filesystem"`
	Network         NetworkPolicy    `yaml:"network" json:"network"`
	Process         ProcessPolicy    `yaml:"process" json:"process"`
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

// Validate validates the sandbox policy for correctness.
// Returns an error if the policy is invalid.
func (p *SandboxPolicy) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("policy name is required")
	}

	if len(p.PackageManagers) == 0 {
		return fmt.Errorf("policy must specify at least one package manager")
	}

	hasRules := len(p.Filesystem.AllowRead) > 0 ||
		len(p.Filesystem.AllowWrite) > 0 ||
		len(p.Filesystem.DenyRead) > 0 ||
		len(p.Filesystem.DenyWrite) > 0 ||
		len(p.Network.AllowOutbound) > 0 ||
		len(p.Network.DenyOutbound) > 0 ||
		len(p.Process.AllowExec) > 0 ||
		len(p.Process.DenyExec) > 0

	if !hasRules {
		return fmt.Errorf("policy must define at least one access rule")
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
