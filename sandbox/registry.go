package sandbox

import (
	"embed"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
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
	presets        PresetRegistry
	templates      map[string]string
}

func newDefaultProfileRegistry(opts ...RegistryOption) (*defaultProfileRegistry, error) {
	options := &registryOptions{}
	for _, opt := range opts {
		opt(options)
	}

	presets := options.presetRegistry
	if presets == nil {
		builtinOnly, err := NewPresetRegistry()
		if err != nil {
			return nil, err
		}
		presets = builtinOnly
	}

	registry := &defaultProfileRegistry{
		profiles:       make(map[string]*SandboxPolicy),
		builtins:       make(map[string]struct{}),
		builtinYAML:    make(map[string][]byte),
		userProfileDir: options.userProfileDir,
		presets:        presets,
		templates:      options.templates,
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

		// embed.FS paths are always slash-separated, filepath.Join would
		// break on Windows.
		data, err := profilesFS.ReadFile(path.Join("profiles", entry.Name()))
		if err != nil {
			return fmt.Errorf("failed to read profile %s: %w", entry.Name(), err)
		}

		policy, err := parsePolicy(data)
		if err != nil {
			return fmt.Errorf("failed to parse profile %s: %w: %w", entry.Name(), ErrProfileInvalid, err)
		}

		// Basic validation (without inheritance resolution)
		if err := policy.Validate(); err != nil {
			return fmt.Errorf("invalid profile %s: %w: %w", entry.Name(), ErrProfileInvalid, err)
		}

		r.mu.Lock()
		r.profiles[policy.Name] = policy
		r.builtins[policy.Name] = struct{}{}
		r.builtinYAML[policy.Name] = data
		r.mu.Unlock()
	}

	// Second pass: resolve inheritance for every profile before any preset
	// expands, so a child merges its parent's preset names and expands them
	// once, whatever order the map iterates in.
	r.mu.Lock()
	defer r.mu.Unlock()

	names := make([]string, 0, len(r.profiles))
	for name := range r.profiles {
		names = append(names, name)
	}
	sort.Strings(names)

	derived := make(map[string]bool, len(names))
	for _, name := range names {
		derived[name] = r.profiles[name].Inherits != ""
		if err := r.resolveBuiltinInheritance(name, nil); err != nil {
			return fmt.Errorf("failed to resolve inheritance for profile %s: %w", name, err)
		}
	}

	for _, name := range names {
		policy := r.profiles[name]
		if err := r.applyPresets(policy); err != nil {
			return fmt.Errorf("failed to apply presets for profile %s: %w", name, err)
		}

		if derived[name] || len(policy.Presets) > 0 {
			if err := policy.ValidateResolved(); err != nil {
				return fmt.Errorf("invalid profile %s after inheritance: %w: %w", name, ErrProfileInvalid, err)
			}
		}
	}

	return nil
}

// An unknown preset is a hard error so profile authors get immediate
// feedback instead of a silently under-provisioned sandbox at run time.
func (r *defaultProfileRegistry) applyPresets(policy *SandboxPolicy) error {
	for _, name := range policy.Presets {
		info, err := r.presets.Get(name)
		if err != nil {
			return fmt.Errorf("preset %s referenced by profile %s: %w", name, policy.Name, err)
		}

		info.Preset.ApplyToPolicy(policy)
	}

	return nil
}

// resolveBuiltinInheritance resolves the chain of a built-in profile in
// place. A built-in may inherit only from a built-in. The parent resolves
// first, so a chain of any depth merges from its base down. visiting holds
// the names on the current path, so a cycle is an error and not a hang.
// Assumes registry mutex is already held.
func (r *defaultProfileRegistry) resolveBuiltinInheritance(name string, visiting []string) error {
	policy := r.profiles[name]
	if policy.Inherits == "" {
		if len(policy.Lineage) == 0 {
			policy.Lineage = []string{name}
		}
		return nil
	}

	if slices.Contains(visiting, name) {
		return inheritanceCycleError(append(visiting, name))
	}
	visiting = append(visiting, name)

	parentName := policy.Inherits
	if _, isBuiltin := r.builtins[parentName]; !isBuiltin {
		return fmt.Errorf("%w: parent profile '%s' (a built-in profile can inherit only from a built-in profile)", ErrProfileNotFound, parentName)
	}

	if err := r.resolveBuiltinInheritance(parentName, visiting); err != nil {
		return err
	}

	mergeInherited(policy, r.profiles[parentName], name)
	return nil
}

// mergeInherited merges parent into child, records the chain and clears the
// inherits field to mark the child as resolved.
func mergeInherited(child, parent *SandboxPolicy, childID string) {
	child.MergeWithParent(parent)
	child.Lineage = append(append([]string(nil), parent.Lineage...), childID)
	child.Inherits = ""
}

func inheritanceCycleError(chain []string) error {
	return fmt.Errorf("%w: inheritance cycle: %s", ErrProfileInvalid, strings.Join(chain, " < "))
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

	return nil, fmt.Errorf("%w: %s (not a built-in profile, no matching user profile, and file does not exist)", ErrProfileNotFound, name)
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

// LoadCustomProfile loads a policy from a custom YAML file path and
// resolves its inheritance chain. A parent is a built-in profile, a
// policy template, a user profile or a file path, in that order. A relative
// path is read from the directory of the file that names it.
func (r *defaultProfileRegistry) LoadCustomProfile(path string) (*SandboxPolicy, error) {
	return r.loadCustomProfile(path, nil)
}

// loadCustomProfile loads path with visiting as the chain of profile files
// above it, so a cycle through files is an error and not a hang.
func (r *defaultProfileRegistry) loadCustomProfile(path string, visiting []string) (*SandboxPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read custom profile %s: %w", path, err)
	}

	policy, err := parsePolicy(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse custom profile %s: %w: %w", path, ErrProfileInvalid, err)
	}

	// Basic validation
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("invalid custom profile %s: %w: %w", path, ErrProfileInvalid, err)
	}

	if policy.Inherits != "" {
		parent, err := r.resolveParent(policy.Inherits, path, visiting)
		if err != nil {
			return nil, fmt.Errorf("custom profile %s: %w", path, err)
		}

		mergeInherited(policy, parent, path)
	} else {
		policy.Lineage = []string{path}
	}

	if err := r.applyPresets(policy); err != nil {
		return nil, fmt.Errorf("custom profile %s: %w", path, err)
	}

	// Validate after inheritance resolution
	if err := policy.ValidateResolved(); err != nil {
		return nil, fmt.Errorf("invalid custom profile %s after inheritance: %w: %w", path, ErrProfileInvalid, err)
	}

	r.mu.Lock()
	r.profiles[path] = policy
	r.mu.Unlock()

	return policy, nil
}

// resolveParent finds and loads the profile that childPath inherits from.
func (r *defaultProfileRegistry) resolveParent(ref, childPath string, visiting []string) (*SandboxPolicy, error) {
	childID := profileFileID(childPath)
	if slices.Contains(visiting, childID) {
		return nil, inheritanceCycleError(append(visiting, childID))
	}
	visiting = append(visiting, childID)

	r.mu.RLock()
	_, isBuiltin := r.builtins[ref]
	builtin := r.profiles[ref]
	templatePath, isTemplate := r.templates[ref]
	r.mu.RUnlock()

	if isBuiltin {
		return builtin, nil
	}

	parentPath := templatePath
	if !isTemplate {
		userPath, found, err := r.findUserProfileByName(ref)
		if err != nil {
			return nil, err
		}
		switch {
		case found:
			parentPath = userPath
		case filepath.IsAbs(ref):
			parentPath = ref
		default:
			parentPath = filepath.Join(filepath.Dir(childPath), ref)
		}
	}

	if !fileExists(parentPath) {
		return nil, fmt.Errorf("%w: inherits from unknown profile '%s' (not a built-in profile, a policy template, a user profile, or a file)", ErrProfileNotFound, ref)
	}

	if slices.Contains(visiting, profileFileID(parentPath)) {
		return nil, inheritanceCycleError(append(visiting, profileFileID(parentPath)))
	}

	parent, err := r.loadCustomProfile(parentPath, visiting)
	if err != nil {
		return nil, err
	}

	return parent, nil
}

// profileFileID identifies a profile file for cycle detection. Two paths
// that name one file get one ID.
func profileFileID(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return filepath.Clean(abs)
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
			Inherits:        p.Parent(),
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
