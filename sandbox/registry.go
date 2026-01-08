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
func (r *defaultProfileRegistry) loadBuiltinProfiles() error {
	entries, err := profilesFS.ReadDir("profiles")
	if err != nil {
		return fmt.Errorf("failed to read profiles directory: %w", err)
	}

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

		if err := policy.Validate(); err != nil {
			return fmt.Errorf("invalid profile %s: %w", entry.Name(), err)
		}

		r.mu.Lock()
		r.profiles[policy.Name] = policy
		r.mu.Unlock()
	}

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
func (r *defaultProfileRegistry) LoadCustomProfile(path string) (*SandboxPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read custom profile %s: %w", path, err)
	}

	policy, err := parsePolicy(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse custom profile %s: %w", path, err)
	}

	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("invalid custom profile %s: %w", path, err)
	}

	r.mu.Lock()
	r.profiles[policy.Name] = policy
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
