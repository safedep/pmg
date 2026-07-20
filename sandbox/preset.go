package sandbox

import (
	"bytes"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox/util"
	"gopkg.in/yaml.v3"
)

// PresetSchemaVersion is the highest preset schema version this binary
// understands. Presets declaring a newer version are rejected so that a
// future registry can ship evolved schemas without old binaries silently
// misreading them.
const PresetSchemaVersion = 1

const presetKind = "preset"

// PresetMetadata carries descriptive, filterable attributes. Metadata never
// affects enforcement.
type PresetMetadata struct {
	Author string   `yaml:"author,omitempty" json:"author,omitempty"`
	Labels []string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// PresetFilesystem lists filesystem allowances. There are intentionally no
// deny fields: presets are additive-only.
type PresetFilesystem struct {
	AllowRead  []string `yaml:"allow_read,omitempty" json:"allow_read,omitempty"`
	AllowWrite []string `yaml:"allow_write,omitempty" json:"allow_write,omitempty"`
}

// PresetNetwork lists network allowances.
type PresetNetwork struct {
	AllowOutbound []string `yaml:"allow_outbound,omitempty" json:"allow_outbound,omitempty"`
	AllowBind     []string `yaml:"allow_bind,omitempty" json:"allow_bind,omitempty"`
}

// PresetProcess lists process execution allowances.
type PresetProcess struct {
	AllowExec []string `yaml:"allow_exec,omitempty" json:"allow_exec,omitempty"`
}

// PresetEnvironment lists environment variable allowances (name globs).
type PresetEnvironment struct {
	Allow []string `yaml:"allow,omitempty" json:"allow,omitempty"`
}

// Preset is a named, additive-only bundle of sandbox allowances describing
// what one workload (git hooks, a dev server, ...) legitimately needs. It is
// structurally a reusable set of `pmg sandbox allow` entries: same trust
// model, same enforcement mechanics. Mandatory denies still apply except via
// the existing exact-match suppression in util.GetMandatoryDenyPatterns.
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

// ParsePreset decodes preset YAML strictly: unknown fields (including any
// deny_* key) are errors, keeping the additive-only contract structural.
func ParsePreset(data []byte) (*Preset, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var preset Preset
	if err := dec.Decode(&preset); err != nil {
		return nil, fmt.Errorf("failed to parse preset YAML: %w", err)
	}

	return &preset, nil
}

// Validate checks the preset against the schema contract described in
// docs/sandbox-presets.md.
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
		len(p.Network.AllowOutbound) + len(p.Network.AllowBind) +
		len(p.Process.AllowExec) + len(p.Environment.Allow)
	if ruleCount == 0 {
		return fmt.Errorf("preset %s must define at least one allowance", p.Name)
	}

	for _, entry := range p.Filesystem.AllowRead {
		if err := validatePresetPath(entry); err != nil {
			return fmt.Errorf("preset %s allow_read: %w", p.Name, err)
		}
	}
	for _, entry := range p.Filesystem.AllowWrite {
		if err := validatePresetPath(entry); err != nil {
			return fmt.Errorf("preset %s allow_write: %w", p.Name, err)
		}
	}
	for _, entry := range p.Process.AllowExec {
		if err := validatePresetPath(entry); err != nil {
			return fmt.Errorf("preset %s allow_exec: %w", p.Name, err)
		}
	}
	for _, entry := range p.Network.AllowBind {
		if err := validatePresetBind(entry); err != nil {
			return fmt.Errorf("preset %s allow_bind: %w", p.Name, err)
		}
	}
	for _, entry := range p.Network.AllowOutbound {
		if err := validatePresetOutbound(entry); err != nil {
			return fmt.Errorf("preset %s allow_outbound: %w", p.Name, err)
		}
	}
	for _, entry := range p.Environment.Allow {
		if err := validatePresetEnv(entry); err != nil {
			return fmt.Errorf("preset %s environment.allow: %w", p.Name, err)
		}
	}

	return nil
}

// validatePresetPath enforces anchoring so a preset cannot allow arbitrary
// host locations: entries must start at ${CWD}, ${HOME} or ${TMPDIR} and
// cannot traverse out or name known sensitive files.
func validatePresetPath(entry string) error {
	anchored := strings.HasPrefix(entry, util.VarCWD+"/") ||
		strings.HasPrefix(entry, util.VarHome+"/") ||
		strings.HasPrefix(entry, util.VarTMPDir+"/")
	if !anchored {
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

func validatePresetOutbound(entry string) error {
	host, port, err := net.SplitHostPort(entry)
	if err != nil {
		return fmt.Errorf("outbound %q must be host:port: %w", entry, err)
	}

	if strings.ContainsAny(host, "*?") || host == "" {
		return fmt.Errorf("outbound host %q must be an exact host, wildcards are not allowed", host)
	}

	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("outbound port %q must be numeric, wildcards are not allowed", port)
	}

	return nil
}

func validatePresetEnv(entry string) error {
	trimmed := strings.Trim(entry, "*")
	if trimmed == "" {
		return fmt.Errorf("entry %q is too broad, name at least part of the variable", entry)
	}

	if strings.ContainsAny(entry, "=/\\ \t") {
		return fmt.Errorf("entry %q is not a valid variable name glob", entry)
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

// ApplyToPolicy unions the preset's allowances into the policy: allow lists
// are extended with dedupe and bind entries enable AllowNetworkBind so
// translators emit bind rules. Deny lists are never touched, unlike explicit
// `pmg sandbox allow` overrides: a deny authored in a profile always wins
// over a preset allowance (deny has higher priority), keeping presets
// strictly additive. Mandatory denies computed by the platform translators
// are unaffected except through the existing exact-match suppression.
func (p *Preset) ApplyToPolicy(policy *SandboxPolicy) {
	policy.Filesystem.AllowRead = unionStringSlices(policy.Filesystem.AllowRead, p.Filesystem.AllowRead)
	policy.Filesystem.AllowWrite = unionStringSlices(policy.Filesystem.AllowWrite, p.Filesystem.AllowWrite)
	policy.Process.AllowExec = unionStringSlices(policy.Process.AllowExec, p.Process.AllowExec)

	policy.Network.AllowOutbound = unionStringSlices(policy.Network.AllowOutbound, p.Network.AllowOutbound)
	policy.Network.AllowBind = unionStringSlices(policy.Network.AllowBind, p.Network.AllowBind)
	if len(p.Network.AllowBind) > 0 {
		policy.AllowNetworkBind = utils.PtrTo(true)
	}

	policy.Environment.Allow = unionStringSlices(policy.Environment.Allow, p.Environment.Allow)
}

// presetFileName reports whether a file name looks like a preset YAML file
// and returns the bare preset name.
func presetFileName(fileName string) (string, bool) {
	ext := filepath.Ext(fileName)
	if ext != ".yml" && ext != ".yaml" {
		return "", false
	}
	return strings.TrimSuffix(fileName, ext), true
}
