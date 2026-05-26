package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"gopkg.in/yaml.v3"
)

// OverlaySchemaVersion is bumped when the on-disk YAML layout changes incompatibly.
const OverlaySchemaVersion = 1

const overlayFileSuffix = ".yml"

// Overlay is the on-disk representation of a per-repo allow-set. One file per
// repo, named by sha256(repo_root)[:16], lives under SandboxOverlayDir().
type Overlay struct {
	SchemaVersion int            `yaml:"schema_version"`
	RepoRoot      string         `yaml:"repo_root"`
	CreatedAt     time.Time      `yaml:"created_at,omitempty"`
	UpdatedAt     time.Time      `yaml:"updated_at,omitempty"`
	Allow         []OverlayAllow `yaml:"allow"`
}

// OverlayAllow is a single persisted allow entry. The field shape matches
// config.SandboxAllowOverride so conversion is mechanical.
type OverlayAllow struct {
	Type  config.SandboxAllowType `yaml:"type"`
	Value string                  `yaml:"value"`
}

// OverlayListEntry pairs an Overlay with the file path it was loaded from,
// for `pmg sandbox project list` output.
type OverlayListEntry struct {
	Path    string
	Overlay Overlay
}

// Add appends entry when no (Type, Value) duplicate already exists. Returns
// true when added, false when the entry was a duplicate.
func (o *Overlay) Add(entry OverlayAllow) bool {
	for _, existing := range o.Allow {
		if existing.Type == entry.Type && existing.Value == entry.Value {
			return false
		}
	}
	o.Allow = append(o.Allow, entry)
	return true
}

// ToAllowOverrides converts overlay entries to the runtime override shape used
// by sandbox/executor.applyRuntimeOverrides.
func (o *Overlay) ToAllowOverrides() []config.SandboxAllowOverride {
	out := make([]config.SandboxAllowOverride, 0, len(o.Allow))
	for _, a := range o.Allow {
		out = append(out, config.SandboxAllowOverride{
			Type:  a.Type,
			Value: a.Value,
			Raw:   fmt.Sprintf("%s=%s", a.Type, a.Value),
		})
	}
	return out
}

// ResolveRepoRoot returns the git toplevel for cwd, falling back to cwd itself
// when not inside a git work tree. The returned path is filepath.Clean'd and
// has its symlinks evaluated where possible so it forms a stable key.
func ResolveRepoRoot(cwd string) (string, error) {
	if cwd == "" {
		return "", errors.New("overlay: empty cwd")
	}

	root := cwd
	cmd := exec.Command("git", "-C", cwd, "rev-parse", "--show-toplevel")
	if out, err := cmd.Output(); err == nil {
		if s := strings.TrimSpace(string(out)); s != "" {
			root = s
		}
	}

	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	} else if !os.IsNotExist(err) {
		// A genuine resolution failure (permissions, broken mid-path symlink)
		// leaves us with a non-canonical key. Surface it so users can see why
		// their overlay does not match across runs.
		log.Warnf("overlay: eval symlinks for %s: %v", root, err)
	}
	return filepath.Clean(root), nil
}

// overlayFileFor returns the canonical absolute path of a repo's overlay file
// inside dir. The filename is sha256(repo_root)[:16] so we never have to
// path-escape the repo root.
func overlayFileFor(dir, repoRoot string) string {
	sum := sha256.Sum256([]byte(repoRoot))
	name := hex.EncodeToString(sum[:])[:16] + overlayFileSuffix
	return filepath.Join(dir, name)
}

// SaveOverlay writes overlay to dir, creating dir lazily. The schema version,
// repo root, and updated timestamp are normalized. CreatedAt is preserved from
// an existing file when present, otherwise set to now. Returns the path
// written.
func SaveOverlay(dir, repoRoot string, overlay *Overlay) (string, error) {
	if dir == "" {
		return "", errors.New("overlay: empty directory")
	}
	if repoRoot == "" {
		return "", errors.New("overlay: empty repo root")
	}
	if overlay == nil {
		return "", errors.New("overlay: nil overlay")
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("overlay: create dir: %w", err)
	}

	path := overlayFileFor(dir, repoRoot)
	now := time.Now().UTC()

	overlay.SchemaVersion = OverlaySchemaVersion
	overlay.RepoRoot = repoRoot
	if overlay.CreatedAt.IsZero() {
		overlay.CreatedAt = now
		if existing, err := loadOverlayFile(path); err == nil && existing != nil && !existing.CreatedAt.IsZero() {
			overlay.CreatedAt = existing.CreatedAt
		}
	}
	overlay.UpdatedAt = now

	data, err := yaml.Marshal(overlay)
	if err != nil {
		return "", fmt.Errorf("overlay: marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("overlay: write: %w", err)
	}
	return path, nil
}

// LoadOverlayForRepo returns the overlay for repoRoot in dir, or (nil, "", nil)
// when the file is missing. Returns an error only for genuine IO or parse
// failures so callers can treat absence as "no overlay" without sniffing.
func LoadOverlayForRepo(dir, repoRoot string) (*Overlay, string, error) {
	if dir == "" || repoRoot == "" {
		return nil, "", nil
	}
	path := overlayFileFor(dir, repoRoot)
	overlay, err := loadOverlayFile(path)
	if err != nil || overlay == nil {
		return nil, "", err
	}
	return overlay, path, nil
}

func loadOverlayFile(path string) (*Overlay, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("overlay: read %s: %w", path, err)
	}
	var overlay Overlay
	if err := yaml.Unmarshal(data, &overlay); err != nil {
		return nil, fmt.Errorf("overlay: parse %s: %w", path, err)
	}
	if overlay.SchemaVersion != 0 && overlay.SchemaVersion != OverlaySchemaVersion {
		return nil, fmt.Errorf("overlay: %s has unknown schema_version %d", path, overlay.SchemaVersion)
	}
	return &overlay, nil
}

// DeleteOverlayForRepo removes the overlay file for repoRoot in dir. A missing
// file is not an error so callers can treat reset as idempotent.
func DeleteOverlayForRepo(dir, repoRoot string) error {
	path := overlayFileFor(dir, repoRoot)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("overlay: remove %s: %w", path, err)
	}
	return nil
}

// ListOverlays returns every readable overlay under dir, sorted by RepoRoot.
// A missing dir yields an empty slice with no error.
func ListOverlays(dir string) ([]OverlayListEntry, error) {
	if dir == "" {
		return nil, nil
	}
	dirents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("overlay: read dir: %w", err)
	}

	out := make([]OverlayListEntry, 0, len(dirents))
	for _, d := range dirents {
		if d.IsDir() || !strings.HasSuffix(d.Name(), overlayFileSuffix) {
			continue
		}
		path := filepath.Join(dir, d.Name())
		overlay, err := loadOverlayFile(path)
		if err != nil || overlay == nil {
			// Skip corrupt files rather than failing the whole list, so users
			// can still inspect/prune via the same command.
			continue
		}
		out = append(out, OverlayListEntry{Path: path, Overlay: *overlay})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Overlay.RepoRoot < out[j].Overlay.RepoRoot })
	return out, nil
}
