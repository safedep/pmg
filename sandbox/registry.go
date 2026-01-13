package sandbox

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed profiles/*.yml
var profilesFS embed.FS

type defaultProfileRegistry struct {
	mu       sync.RWMutex
	profiles map[string]*SandboxPolicy
}

func newDefaultProfileRegistry() (*defaultProfileRegistry, error) {
	registry := &defaultProfileRegistry{
		profiles: make(map[string]*SandboxPolicy),
	}

	if err := registry.loadBuiltinProfiles(); err != nil {
		return nil, fmt.Errorf("failed to load built-in sandbox profiles: %w", err)
	}

	return registry, nil
}

// loadBuiltinProfiles loads all built-in YAML profiles from the embedded filesystem.
// Inheritance is resolved in a second pass after all profiles are loaded.
func (r *defaultProfileRegistry) loadBuiltinProfiles() error {
	entries, err := profilesFS.ReadDir("profiles")
	if err != nil {
		return fmt.Errorf("failed to read profiles directory: %w", err)
	}

	// First pass: load all profiles without resolving inheritance
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		profilePath := filepath.Join("profiles", entry.Name())
		data, err := profilesFS.ReadFile(profilePath)
		if err != nil {
			return fmt.Errorf("failed to read profile %s: %w", entry.Name(), err)
		}

		policy, err := parsePolicy(data)
		if err != nil {
			return fmt.Errorf("failed to parse profile %s: %w", entry.Name(), err)
		}

		// Basic validation (without inheritance resolution)
		if err := policy.Validate(); err != nil {
			return fmt.Errorf("invalid profile %s: %w", entry.Name(), err)
		}

		r.mu.Lock()
		r.profiles[policy.Name] = policy
		r.mu.Unlock()
	}

	// Second pass: resolve inheritance and validate
	r.mu.Lock()
	defer r.mu.Unlock()

	for name, policy := range r.profiles {
		if policy.Inherits != "" {
			if err := r.resolveInheritance(policy); err != nil {
				return fmt.Errorf("failed to resolve inheritance for profile %s: %w", name, err)
			}

			// Validate after inheritance resolution
			if err := policy.ValidateResolved(); err != nil {
				return fmt.Errorf("invalid profile %s after inheritance: %w", name, err)
			}
		}
	}

	return nil
}

// resolveInheritance resolves the inheritance chain for a policy.
// This function is called during registry initialization and modifies the policy in place.
// Assumes registry mutex is already held.
func (r *defaultProfileRegistry) resolveInheritance(child *SandboxPolicy) error {
	if child.Inherits == "" {
		return nil
	}

	// Look up parent profile (must be a built-in profile)
	parent, exists := r.profiles[child.Inherits]
	if !exists {
		return fmt.Errorf("parent profile '%s' not found (only built-in profiles can be inherited)", child.Inherits)
	}

	// Prevent inheritance chains (parent must not itself inherit)
	if parent.Inherits != "" {
		return fmt.Errorf("inheritance chains not allowed: parent profile '%s' inherits from '%s'", parent.Name, parent.Inherits)
	}

	// Merge parent into child
	child.MergeWithParent(parent)

	// Clear the inherits field after resolution to indicate it's been processed
	child.Inherits = ""

	return nil
}

// GetProfile retrieves a policy by name.
func (r *defaultProfileRegistry) GetProfile(name string) (*SandboxPolicy, error) {
	r.mu.RLock()
	if policy, exists := r.profiles[name]; exists {
		r.mu.RUnlock()
		return policy, nil
	}
	r.mu.RUnlock()

	if fileExists(name) {
		return r.LoadCustomProfile(name)
	}

	return nil, fmt.Errorf("sandbox profile not found: %s (not a built-in profile and file does not exist)", name)
}

// LoadCustomProfile loads a policy from a custom YAML file path.
// Inheritance is resolved if the profile inherits from a built-in profile.
func (r *defaultProfileRegistry) LoadCustomProfile(path string) (*SandboxPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read custom profile %s: %w", path, err)
	}

	policy, err := parsePolicy(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse custom profile %s: %w", path, err)
	}

	// Basic validation
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("invalid custom profile %s: %w", path, err)
	}

	// Resolve inheritance if present
	if policy.Inherits != "" {
		r.mu.RLock()
		parent, exists := r.profiles[policy.Inherits]
		r.mu.RUnlock()

		if !exists {
			return nil, fmt.Errorf("custom profile %s inherits from unknown profile '%s' (only built-in profiles can be inherited)", path, policy.Inherits)
		}

		// Prevent inheritance chains
		if parent.Inherits != "" {
			return nil, fmt.Errorf("custom profile %s: parent profile '%s' inherits from '%s' (chains not allowed)", path, parent.Name, parent.Inherits)
		}

		// Merge parent into child
		policy.MergeWithParent(parent)
		policy.Inherits = ""
	}

	// Validate after inheritance resolution
	if err := policy.ValidateResolved(); err != nil {
		return nil, fmt.Errorf("invalid custom profile %s after inheritance: %w", path, err)
	}

	r.mu.Lock()
	r.profiles[path] = policy
	r.mu.Unlock()

	return policy, nil
}

// ListProfiles returns the names of all built-in profiles.
func (r *defaultProfileRegistry) ListProfiles() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	profiles := make([]string, 0, len(r.profiles))
	for name := range r.profiles {
		profiles = append(profiles, name)
	}

	return profiles
}

func parsePolicy(data []byte) (*SandboxPolicy, error) {
	var policy SandboxPolicy

	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy from YAML: %w", err)
	}

	return &policy, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	return !info.IsDir()
}
