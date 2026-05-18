package sandbox

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/safedep/dry/log"
	"gopkg.in/yaml.v3"
)

//go:embed profiles/*.yml
var profilesFS embed.FS

type defaultProfileRegistry struct {
	mu             sync.RWMutex
	profiles       map[string]*SandboxPolicy
	builtins       map[string]struct{}
	builtinYAML    map[string][]byte
	userProfileDir string
}

func newDefaultProfileRegistry(opts ...RegistryOption) (*defaultProfileRegistry, error) {
	options := &registryOptions{}
	for _, opt := range opts {
		opt(options)
	}

	registry := &defaultProfileRegistry{
		profiles:       make(map[string]*SandboxPolicy),
		builtins:       make(map[string]struct{}),
		builtinYAML:    make(map[string][]byte),
		userProfileDir: options.userProfileDir,
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
		r.builtins[policy.Name] = struct{}{}
		r.builtinYAML[policy.Name] = data
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
// Resolution order: built-in profiles first, then user profile directory
// (by bare name, looking up <name>.yml or <name>.yaml), then a literal file path.
func (r *defaultProfileRegistry) GetProfile(name string) (*SandboxPolicy, error) {
	r.mu.RLock()
	if _, isBuiltin := r.builtins[name]; isBuiltin {
		policy := r.profiles[name]
		r.mu.RUnlock()
		return policy, nil
	}
	r.mu.RUnlock()

	path, found, err := r.findUserProfileByName(name)
	if err != nil {
		return nil, err
	}
	if found {
		return r.LoadCustomProfile(path)
	}

	if fileExists(name) {
		return r.LoadCustomProfile(name)
	}

	return nil, fmt.Errorf("sandbox profile not found: %s (not a built-in profile, no matching user profile, and file does not exist)", name)
}

// findUserProfileByName looks for `<name>.yml` then `<name>.yaml` under
// the user profile directory. Returns the absolute path if found.
func (r *defaultProfileRegistry) findUserProfileByName(name string) (string, bool, error) {
	if r.userProfileDir == "" || !isBareProfileName(name) {
		return "", false, nil
	}

	files, err := r.userProfileFiles()
	if err != nil {
		return "", false, fmt.Errorf("failed to read user profile directory %s: %w", r.userProfileDir, err)
	}
	for _, file := range files {
		if file.name == name {
			return file.path, true, nil
		}
	}

	return "", false, nil
}

func isBareProfileName(name string) bool {
	return name != "" && name == filepath.Base(name) && name != "." && name != ".."
}

// UserProfileDir returns the directory scanned for user profiles.
func (r *defaultProfileRegistry) UserProfileDir() string {
	return r.userProfileDir
}

// ListUserProfiles enumerates *.yml / *.yaml files under UserProfileDir().
// A missing directory returns an empty slice with no error. Profiles whose
// name collides with a built-in are marked as Shadowed.
func (r *defaultProfileRegistry) ListUserProfiles() ([]ProfileInfo, error) {
	files, err := r.userProfileFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to read user profile directory %s: %w", r.userProfileDir, err)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	profiles := make([]ProfileInfo, 0, len(files))
	for _, file := range files {
		_, shadowed := r.builtins[file.name]

		profiles = append(profiles, ProfileInfo{
			Name:     file.name,
			Path:     file.path,
			Shadowed: shadowed,
		})
	}

	return profiles, nil
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

// ListProfiles returns all discoverable profiles: built-ins first, then user
// profiles (including shadowed entries so the cmd layer can warn the user).
func (r *defaultProfileRegistry) ListProfiles() ([]ProfileSummary, error) {
	r.mu.RLock()
	builtinNames := make([]string, 0, len(r.builtins))
	for name := range r.builtins {
		builtinNames = append(builtinNames, name)
	}
	sort.Strings(builtinNames)

	summaries := make([]ProfileSummary, 0, len(builtinNames))
	for _, name := range builtinNames {
		p := r.profiles[name]
		summaries = append(summaries, ProfileSummary{
			Name:            name,
			Source:          ProfileSourceBuiltin,
			Inherits:        p.Inherits,
			PackageManagers: append([]string(nil), p.PackageManagers...),
			Description:     p.Description,
		})
	}
	r.mu.RUnlock()

	files, err := r.userProfileFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to read user profile directory %s: %w", r.userProfileDir, err)
	}

	userEntries := make([]ProfileSummary, 0, len(files))
	for _, file := range files {
		r.mu.RLock()
		_, shadowed := r.builtins[file.name]
		r.mu.RUnlock()

		summary := ProfileSummary{
			Name:     file.name,
			Source:   ProfileSourceUser,
			Path:     file.path,
			Shadowed: shadowed,
		}

		data, err := os.ReadFile(file.path)
		if err != nil {
			log.Warnf("failed to read user profile %s: %v", file.path, err)
			userEntries = append(userEntries, summary)
			continue
		}

		var parsed SandboxPolicy
		if err := yaml.Unmarshal(data, &parsed); err != nil {
			log.Warnf("failed to parse user profile %s: %v", file.path, err)
			userEntries = append(userEntries, summary)
			continue
		}

		summary.Inherits = parsed.Inherits
		summary.PackageManagers = parsed.PackageManagers
		summary.Description = parsed.Description
		userEntries = append(userEntries, summary)
	}

	sort.Slice(userEntries, func(i, j int) bool {
		return userEntries[i].Name < userEntries[j].Name
	})

	return append(summaries, userEntries...), nil
}

type userProfileFile struct {
	name string
	path string
}

func (r *defaultProfileRegistry) userProfileFiles() ([]userProfileFile, error) {
	if r.userProfileDir == "" {
		return nil, nil
	}

	entries, err := os.ReadDir(r.userProfileDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	byName := make(map[string]userProfileFile, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := filepath.Ext(entry.Name())
		if ext != ".yml" && ext != ".yaml" {
			continue
		}

		name := strings.TrimSuffix(entry.Name(), ext)
		if !isBareProfileName(name) {
			continue
		}

		file := userProfileFile{
			name: name,
			path: filepath.Join(r.userProfileDir, entry.Name()),
		}

		if existing, ok := byName[name]; ok && filepath.Ext(existing.path) == ".yml" {
			continue
		}
		byName[name] = file
	}

	files := make([]userProfileFile, 0, len(byName))
	for _, file := range byName {
		files = append(files, file)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	return files, nil
}

// BuiltinProfileYAML returns the embedded YAML for a built-in profile.
func (r *defaultProfileRegistry) BuiltinProfileYAML(name string) ([]byte, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	data, ok := r.builtinYAML[name]
	if !ok {
		return nil, false
	}

	out := make([]byte, len(data))
	copy(out, data)
	return out, true
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
