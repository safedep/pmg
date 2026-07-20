package sandbox

import (
	"bytes"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox/util"
	"gopkg.in/yaml.v3"
)

// PresetSchemaVersion is the highest preset schema version this binary
// accepts. Newer versions are rejected instead of being silently misread.
const PresetSchemaVersion = 1

const presetKind = "preset"

// PresetMetadata is descriptive and filterable, never enforced.
type PresetMetadata struct {
	Author string   `yaml:"author,omitempty" json:"author,omitempty"`
	Labels []string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// PresetFilesystem lists filesystem allowances.
type PresetFilesystem struct {
	AllowRead  []string `yaml:"allow_read,omitempty" json:"allow_read,omitempty"`
	AllowWrite []string `yaml:"allow_write,omitempty" json:"allow_write,omitempty"`
}

// PresetNetwork lists network allowances. No allow_outbound: platform
// translators are all-or-nothing for outbound, so one entry would mean
// blanket network access far beyond what the preset YAML conveys.
type PresetNetwork struct {
	AllowBind []string `yaml:"allow_bind,omitempty" json:"allow_bind,omitempty"`
}

// PresetProcess lists process execution allowances.
type PresetProcess struct {
	AllowExec []string `yaml:"allow_exec,omitempty" json:"allow_exec,omitempty"`
}

// PresetEnvironment lists environment variable allowances (name globs).
type PresetEnvironment struct {
	Allow []string `yaml:"allow,omitempty" json:"allow,omitempty"`
}

// Preset is a named, additive-only bundle of sandbox allowances for one
// workload. Mandatory denies still apply except via the exact-match
// suppression in util.GetMandatoryDenyPatterns.
type Preset struct {
	SchemaVersion int               `yaml:"schema_version,omitempty" json:"schema_version,omitempty"`
	Kind          string            `yaml:"kind" json:"kind"`
	Name          string            `yaml:"name" json:"name"`
	Description   string            `yaml:"description,omitempty" json:"description,omitempty"`
	Metadata      PresetMetadata    `yaml:"metadata,omitempty" json:"metadata,omitempty"`
	Filesystem    PresetFilesystem  `yaml:"filesystem,omitempty" json:"filesystem,omitempty"`
	Network       PresetNetwork     `yaml:"network,omitempty" json:"network,omitempty"`
	Process       PresetProcess     `yaml:"process,omitempty" json:"process,omitempty"`
	Environment   PresetEnvironment `yaml:"environment,omitempty" json:"environment,omitempty"`
}

var presetNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// ParsePreset decodes strictly: unknown fields (including any deny_* key)
// are errors, keeping the additive-only contract structural.
func ParsePreset(data []byte) (*Preset, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var preset Preset
	if err := dec.Decode(&preset); err != nil {
		return nil, fmt.Errorf("failed to parse preset YAML: %w", err)
	}

	return &preset, nil
}

// Validate enforces the preset schema contract.
func (p *Preset) Validate() error {
	if p.Kind != presetKind {
		return fmt.Errorf("kind must be %q, got %q", presetKind, p.Kind)
	}

	if !presetNameRe.MatchString(p.Name) {
		return fmt.Errorf("preset name %q must be lowercase alphanumeric with dashes", p.Name)
	}

	if p.SchemaVersion > PresetSchemaVersion {
		return fmt.Errorf("preset %s declares schema_version %d, this pmg supports up to %d (upgrade pmg)",
			p.Name, p.SchemaVersion, PresetSchemaVersion)
	}

	ruleCount := len(p.Filesystem.AllowRead) + len(p.Filesystem.AllowWrite) +
		len(p.Network.AllowBind) +
		len(p.Process.AllowExec) + len(p.Environment.Allow)
	if ruleCount == 0 {
		return fmt.Errorf("preset %s must define at least one allowance", p.Name)
	}

	for _, entry := range p.Filesystem.AllowRead {
		if err := validatePresetPath(entry, true); err != nil {
			return fmt.Errorf("preset %s allow_read: %w", p.Name, err)
		}
	}
	for _, entry := range p.Filesystem.AllowWrite {
		if err := validatePresetPath(entry, false); err != nil {
			return fmt.Errorf("preset %s allow_write: %w", p.Name, err)
		}
	}
	for _, entry := range p.Process.AllowExec {
		if err := validatePresetPath(entry, false); err != nil {
			return fmt.Errorf("preset %s allow_exec: %w", p.Name, err)
		}
	}
	for _, entry := range p.Network.AllowBind {
		if err := validatePresetBind(entry); err != nil {
			return fmt.Errorf("preset %s allow_bind: %w", p.Name, err)
		}
	}
	for _, entry := range p.Environment.Allow {
		if err := validatePresetEnv(entry); err != nil {
			return fmt.Errorf("preset %s environment.allow: %w", p.Name, err)
		}
	}

	return nil
}

// Anchoring keeps a preset from allowing arbitrary host locations, and
// naming a mandatory-deny target is rejected because an exact-match entry
// would suppress that mandatory deny (see util.GetMandatoryDenyPatterns).
// The one deliberate exception is read access to .git/config, which git
// repo discovery requires and the built-in git preset uses.
func validatePresetPath(entry string, read bool) error {
	var rel string
	for _, anchor := range []string{util.VarCWD, util.VarHome, util.VarTMPDir} {
		if strings.HasPrefix(entry, anchor+"/") {
			rel = strings.TrimPrefix(entry, anchor+"/")
			break
		}
	}
	if rel == "" {
		return fmt.Errorf("path %q must be anchored at ${CWD}/, ${HOME}/ or ${TMPDIR}/", entry)
	}

	for _, segment := range strings.Split(entry, "/") {
		if segment == ".." {
			return fmt.Errorf("path %q must not traverse with '..'", entry)
		}
	}

	if IsSensitiveProjectTarget(entry) {
		return fmt.Errorf("path %q names a sensitive target and cannot be allowed by a preset", entry)
	}

	for _, dangerous := range util.DANGEROUS_FILES {
		if rel == dangerous || strings.HasPrefix(rel, dangerous+"/") {
			return fmt.Errorf("path %q names the protected credential target %q and cannot be allowed by a preset", entry, dangerous)
		}
	}

	if rel == ".git/hooks" || strings.HasPrefix(rel, ".git/hooks/") {
		return fmt.Errorf("path %q: .git/hooks cannot be allowed by a preset", entry)
	}

	if !read && rel == ".git/config" {
		return fmt.Errorf("path %q: .git/config write access cannot be allowed by a preset", entry)
	}

	return nil
}

var loopbackHosts = map[string]bool{
	"localhost": true,
	"127.0.0.1": true,
	"::1":       true,
}

func validatePresetBind(entry string) error {
	host, port, err := net.SplitHostPort(entry)
	if err != nil {
		return fmt.Errorf("bind %q must be host:port: %w", entry, err)
	}

	if !loopbackHosts[host] {
		return fmt.Errorf("bind host %q must be loopback (localhost, 127.0.0.1 or ::1)", host)
	}

	if port != "*" {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return fmt.Errorf("bind port %q must be numeric or '*'", port)
		}
	}

	return nil
}

// Preset env allowances are exact variable names, no glob metacharacters.
// This keeps the authored-deny precedence check exact: a deny pattern (any
// dialect ScrubEnv supports, including character classes) is evaluated
// against the literal name with the same matcher used at scrub time, so no
// glob-vs-glob intersection is ever needed.
func validatePresetEnv(entry string) error {
	if entry == "" || strings.ContainsAny(entry, "*?[]=/\\ \t") {
		return fmt.Errorf("entry %q must be an exact variable name (globs are not allowed in presets)", entry)
	}

	return nil
}

// HasLabel reports whether the preset carries the label (case-insensitive).
func (p *Preset) HasLabel(label string) bool {
	for _, l := range p.Metadata.Labels {
		if strings.EqualFold(l, label) {
			return true
		}
	}
	return false
}

// ApplyToPolicy unions the preset's allowances into the policy. Unlike
// explicit `pmg sandbox allow` overrides it never touches deny lists, so an
// authored deny always wins over a preset allowance.
func (p *Preset) ApplyToPolicy(policy *SandboxPolicy) {
	policy.Filesystem.AllowRead = unionStringSlices(policy.Filesystem.AllowRead, p.Filesystem.AllowRead)
	policy.Filesystem.AllowWrite = unionStringSlices(policy.Filesystem.AllowWrite, p.Filesystem.AllowWrite)
	policy.Process.AllowExec = unionStringSlices(policy.Process.AllowExec, p.Process.AllowExec)

	policy.Network.AllowBind = unionStringSlices(policy.Network.AllowBind, p.Network.AllowBind)
	if len(p.Network.AllowBind) > 0 {
		policy.AllowNetworkBind = utils.PtrTo(true)
	}

	policy.Environment.Allow = unionStringSlices(policy.Environment.Allow, p.filteredEnvAllow(policy))
}

// ScrubEnv is allow-wins, so a preset allowance covered by an authored deny
// must be dropped here or it would override the profile author's deny.
// Allowances are literal names (enforced by validatePresetEnv), so coverage
// is decided by the same matcher ScrubEnv uses at runtime. Surviving entries
// still suppress built-in DANGEROUS_ENV_VARS denies.
func (p *Preset) filteredEnvAllow(policy *SandboxPolicy) []string {
	if len(p.Environment.Allow) == 0 || len(policy.Environment.Deny) == 0 {
		return p.Environment.Allow
	}

	kept := make([]string, 0, len(p.Environment.Allow))
	for _, allow := range p.Environment.Allow {
		if util.EnvNameMatchesAny(allow, policy.Environment.Deny) {
			log.Warnf("preset %s: environment allowance %q dropped, it is covered by an authored deny in policy %s", p.Name, allow, policy.Name)
			continue
		}
		kept = append(kept, allow)
	}
	return kept
}

func presetFileName(fileName string) (string, bool) {
	ext := filepath.Ext(fileName)
	if ext != ".yml" && ext != ".yaml" {
		return "", false
	}
	return strings.TrimSuffix(fileName, ext), true
}
