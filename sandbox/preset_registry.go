package sandbox

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/safedep/dry/log"
)

//go:embed presets/*.yml
var presetsFS embed.FS

// PresetSourceName identifies where a preset was loaded from. Future sources
// (hosted registry, SafeDep cloud sync) plug in as additional PresetSource
// implementations without changing resolution mechanics.
type PresetSourceName string

const (
	PresetSourceBuiltin PresetSourceName = "builtin"
	PresetSourceUser    PresetSourceName = "user"
)

// PresetSource is a read-only provider of presets. Sources are consulted in
// registry order; the first source that knows a name wins.
type PresetSource interface {
	Name() PresetSourceName

	// List returns all valid presets from this source, sorted by name.
	// Invalid preset files are skipped with a warning, never fatal.
	List() ([]PresetInfo, error)

	// Get returns the preset by bare name, or found=false.
	Get(name string) (*PresetInfo, bool, error)
}

// PresetInfo pairs a preset with its provenance for listing and display.
type PresetInfo struct {
	Preset *Preset

	Source PresetSourceName

	// Path is the on-disk file for user presets; "" for builtins.
	Path string

	// Shadowed is true when an earlier source (e.g. builtin) also provides
	// this name and wins during resolution.
	Shadowed bool

	// Raw is the original YAML, preserved so `preset show` can display
	// authored comments (threat notes).
	Raw []byte
}

// PresetRegistry resolves presets across ordered sources.
type PresetRegistry interface {
	// Get resolves a preset by bare name across sources in order.
	Get(name string) (*PresetInfo, error)

	// List enumerates presets from all sources, builtins first, marking
	// user presets shadowed by builtin names.
	List() ([]PresetInfo, error)
}

// PresetFilter narrows List results by metadata. Zero value matches all.
type PresetFilter struct {
	Author string
	Labels []string
}

// Matches applies the filter: author is case-insensitive equality, labels
// must all be present.
func (f PresetFilter) Matches(p *Preset) bool {
	if f.Author != "" && !strings.EqualFold(p.Metadata.Author, f.Author) {
		return false
	}
	for _, label := range f.Labels {
		if !p.HasLabel(label) {
			return false
		}
	}
	return true
}

// FilterPresets returns the subset of infos matching the filter.
func FilterPresets(infos []PresetInfo, filter PresetFilter) []PresetInfo {
	out := make([]PresetInfo, 0, len(infos))
	for _, info := range infos {
		if filter.Matches(info.Preset) {
			out = append(out, info)
		}
	}
	return out
}

type presetRegistry struct {
	sources []PresetSource
}

// PresetRegistryOption configures a PresetRegistry.
type PresetRegistryOption func(*presetRegistryOptions)

type presetRegistryOptions struct {
	userPresetDir string
}

// WithUserPresetDir sets the directory scanned for user (community) presets.
// The directory does not need to exist.
func WithUserPresetDir(dir string) PresetRegistryOption {
	return func(o *presetRegistryOptions) {
		o.userPresetDir = dir
	}
}

// NewPresetRegistry creates a registry over the builtin (embedded) source
// and, when configured, the user preset directory. Builtins always win name
// resolution so an official preset cannot be silently replaced by a local
// file.
func NewPresetRegistry(opts ...PresetRegistryOption) (PresetRegistry, error) {
	options := &presetRegistryOptions{}
	for _, opt := range opts {
		opt(options)
	}

	builtin, err := newBuiltinPresetSource()
	if err != nil {
		return nil, fmt.Errorf("failed to load built-in sandbox presets: %w", err)
	}

	sources := []PresetSource{builtin}
	if options.userPresetDir != "" {
		sources = append(sources, &dirPresetSource{dir: options.userPresetDir})
	}

	return &presetRegistry{sources: sources}, nil
}

func (r *presetRegistry) Get(name string) (*PresetInfo, error) {
	for _, source := range r.sources {
		info, found, err := source.Get(name)
		if err != nil {
			return nil, err
		}
		if found {
			return info, nil
		}
	}

	return nil, fmt.Errorf("%w: preset %s", ErrPresetNotFound, name)
}

func (r *presetRegistry) List() ([]PresetInfo, error) {
	seen := make(map[string]bool)
	out := []PresetInfo{}

	for _, source := range r.sources {
		infos, err := source.List()
		if err != nil {
			return nil, err
		}
		for _, info := range infos {
			info.Shadowed = seen[info.Preset.Name]
			if !info.Shadowed {
				seen[info.Preset.Name] = true
			}
			out = append(out, info)
		}
	}

	return out, nil
}

type builtinPresetSource struct {
	presets map[string]*PresetInfo
}

func newBuiltinPresetSource() (*builtinPresetSource, error) {
	entries, err := presetsFS.ReadDir("presets")
	if err != nil {
		return nil, fmt.Errorf("failed to read presets directory: %w", err)
	}

	source := &builtinPresetSource{presets: make(map[string]*PresetInfo, len(entries))}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if _, ok := presetFileName(entry.Name()); !ok {
			continue
		}

		data, err := presetsFS.ReadFile(filepath.Join("presets", entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to read preset %s: %w", entry.Name(), err)
		}

		preset, err := loadPreset(data)
		if err != nil {
			return nil, fmt.Errorf("invalid built-in preset %s: %w", entry.Name(), err)
		}

		source.presets[preset.Name] = &PresetInfo{
			Preset: preset,
			Source: PresetSourceBuiltin,
			Raw:    data,
		}
	}

	return source, nil
}

func (s *builtinPresetSource) Name() PresetSourceName { return PresetSourceBuiltin }

func (s *builtinPresetSource) List() ([]PresetInfo, error) {
	names := make([]string, 0, len(s.presets))
	for name := range s.presets {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]PresetInfo, 0, len(names))
	for _, name := range names {
		out = append(out, *s.presets[name])
	}
	return out, nil
}

func (s *builtinPresetSource) Get(name string) (*PresetInfo, bool, error) {
	info, ok := s.presets[name]
	if !ok {
		return nil, false, nil
	}
	return info, true, nil
}

// dirPresetSource reads presets from a directory of YAML files. Used for
// user/community presets; a future cloud-synced source is the same shape
// pointed at a managed directory.
type dirPresetSource struct {
	dir string
}

func (s *dirPresetSource) Name() PresetSourceName { return PresetSourceUser }

func (s *dirPresetSource) List() ([]PresetInfo, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read preset directory %s: %w", s.dir, err)
	}

	out := []PresetInfo{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fileBase, ok := presetFileName(entry.Name())
		if !ok {
			continue
		}

		path := filepath.Join(s.dir, entry.Name())
		info, err := s.load(path)
		if err != nil {
			log.Warnf("skipping invalid preset %s: %v", path, err)
			continue
		}

		if info.Preset.Name != fileBase {
			log.Warnf("preset %s: file name %q does not match preset name %q, using preset name", path, fileBase, info.Preset.Name)
		}

		out = append(out, *info)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Preset.Name < out[j].Preset.Name })
	return out, nil
}

func (s *dirPresetSource) Get(name string) (*PresetInfo, bool, error) {
	infos, err := s.List()
	if err != nil {
		return nil, false, err
	}
	for _, info := range infos {
		if info.Preset.Name == name {
			return &info, true, nil
		}
	}
	return nil, false, nil
}

func (s *dirPresetSource) load(path string) (*PresetInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	preset, err := loadPreset(data)
	if err != nil {
		return nil, err
	}

	return &PresetInfo{
		Preset: preset,
		Source: PresetSourceUser,
		Path:   path,
		Raw:    data,
	}, nil
}

func loadPreset(data []byte) (*Preset, error) {
	preset, err := ParsePreset(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPresetInvalid, err)
	}
	if err := preset.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPresetInvalid, err)
	}
	return preset, nil
}
