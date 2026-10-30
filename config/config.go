package config

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	_ "embed"

	"github.com/safedep/pmg/internal/fsutil"
	"github.com/safedep/pmg/internal/platform"
	sandboxutil "github.com/safedep/pmg/sandbox/util"

	"github.com/safedep/dry/log"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/errcodes"
	"github.com/spf13/viper"
)

const (
	// Verbosity level constants for the config file
	VerbositySilent  = "silent"
	VerbosityNormal  = "normal"
	VerbosityVerbose = "verbose"

	// Environment variable key for the insecure installation flag
	pmgInsecureInstallationEnvKey = "PMG_INSECURE_INSTALLATION"

	// Allow overriding the config path from the environment
	pmgConfigDirEnvKey = "PMG_CONFIG_DIR"

	// Allow overriding the cache path from the environment
	pmgCacheDirEnvKey = "PMG_CACHE_DIR"

	// Config path is computed as the user config directory + the default relative path
	// when not overridden by the environment variable
	pmgDefaultHomeRelativePath = "safedep/pmg"

	// Default log directory is relative to the config directory.
	pmgDefaultLogDir = "logs"

	// Default sandbox profile directory is relative to the config directory.
	pmgDefaultSandboxProfileDir = "sandbox/profiles"

	// Default sandbox overlay directory is relative to the config directory.
	// Per-repo overlays persisted by `pmg sandbox allow` live here.
	pmgDefaultSandboxOverlayDir = "sandbox/overlays"

	// Default sandbox preset directory is relative to the config directory.
	// User/community preset YAML files live here.
	pmgDefaultSandboxPresetDir = "sandbox/presets"

	// Default sandbox violation cache directory is relative to the cache root.
	pmgDefaultSandboxViolationCacheDir = "sandbox/violations"

	// Default localdb directory is relative to the cache root.
	pmgDefaultLocalDBDir = "localdb"

	// Default localdb file name for PMG's shared SQLite database.
	pmgDefaultLocalDBFileName = "pmg.db"

	// Config file name.
	// Important: The config file path and the schema should be backward compatible. In case of breaking config
	// changes, we must introduce a new file name and a migration path.
	pmgConfigFileName = "config.yml"
)

//go:embed config.template.yml
var templateConfig string

// Config is the global configuration for PMG that can be persisted or loaded from a given source.
// Here we only define the configuration that can be persisted or loaded from a given source and
// not those that we believe should not be persisted (eg. insecure installation, etc.)
type Config struct {
	// Paranoid enables high-security defaults (e.g., treating suspicious behavior as malicious).
	Paranoid bool `mapstructure:"paranoid"`

	// DisableTelemetry allows turning off telemetry collection.
	DisableTelemetry bool `mapstructure:"disable_telemetry"`

	// TrustedPackages allows for trusting a suspicious package and ignoring the suspicious behaviour for the package in future installations
	TrustedPackages []TrustedPackage `mapstructure:"trusted_packages"`

	// AdvisoryMessage is an optional org-specific message appended to every
	// block output, regardless of which control blocked the installation.
	AdvisoryMessage string `mapstructure:"advisory_message"`

	// SkipEventLogging allows for skipping event logging.
	SkipEventLogging bool `mapstructure:"skip_event_logging"`

	// EventLogRetentionDays is the number of days to retain event logs.
	EventLogRetentionDays int `mapstructure:"event_log_retention_days"`

	// Deprecated: Use Proxy.InstallOnly instead. Kept for backward compatibility with old config files.
	ProxyInstallOnly bool `mapstructure:"proxy_install_only"`

	// Verbosity controls the UI verbosity level. Valid values: "silent", "normal", "verbose".
	Verbosity string `mapstructure:"verbosity"`

	// Sandbox enables sandboxing of package manager processes with controlled filesystem,
	// network, and process execution access. Provides defense-in-depth against supply chain attacks.
	Sandbox SandboxConfig `mapstructure:"sandbox"`

	DependencyCooldown DependencyCooldownConfig `mapstructure:"dependency_cooldown"`

	// AnalysisCache configures the optional cross-run cache of malware-analysis
	// verdicts, so repeat installs of an already-screened dependency graph skip
	// the per-package analysis round-trip.
	AnalysisCache AnalysisCacheConfig `mapstructure:"analysis_cache"`

	Cloud CloudConfig `mapstructure:"cloud"`

	Proxy ProxyConfig `mapstructure:"proxy"`
}

// AnalysisCacheConfig is the umbrella for per-analyzer cross-run caches. Caching
// is analyzer-specific — each analyzer decides what is safe to cache — so config
// is nested per analyzer rather than shared. Today only the Malysis (malware)
// analyzer has a cache; future analyzers can add their own sub-config here.
type AnalysisCacheConfig struct {
	// Malysis configures the cross-run cache for the Malysis malware analyzer.
	Malysis MalysisCacheConfig `mapstructure:"malysis"`
}

// MalysisCacheConfig configures a persistent, cross-run cache of package
// malware-analysis verdicts produced by the Malysis analyzer.
//
// By default PMG keeps an in-memory analysis cache that lives only for the
// duration of a single invocation, so every install re-screens the whole
// resolved graph against the analysis backend. When Enabled, clean (ALLOW)
// verdicts are additionally persisted on disk and reused across runs, which
// makes repeat installs of an unchanged graph fast.
//
// Security trade-off: a version that was clean when first screened but is later
// flagged as malicious is served from cache (and thus allowed) until its entry
// expires; TTL bounds that exposure window. Only ALLOW verdicts are cached —
// suspicious, malicious, and tenant-excluded verdicts are always re-evaluated.
// Disabled by default.
type MalysisCacheConfig struct {
	Enabled bool `mapstructure:"enabled"`

	// TTL is how long a cached verdict remains valid. A non-positive TTL
	// disables persistence (entries are always treated as a miss).
	TTL time.Duration `mapstructure:"ttl"`
}

// CloudConfig configures audit event sync to SafeDep Cloud.
type CloudConfig struct {
	Enabled    bool                `mapstructure:"enabled"`
	EndpointID string              `mapstructure:"endpoint_id"`
	AutoSync   CloudAutoSyncConfig `mapstructure:"auto_sync"`
}

// CloudAutoSyncConfig controls opportunistic background sync of the cloud
// audit WAL. When Enabled, PMG spawns a detached `pmg cloud sync-background`
// child at the end of each invocation, gated by a per-host cooldown so the
// sync does not fire on every command.
type CloudAutoSyncConfig struct {
	Enabled     bool          `mapstructure:"enabled"`
	MinInterval time.Duration `mapstructure:"min_interval"`
	Timeout     time.Duration `mapstructure:"timeout"`
}

type ProxyConfig struct {
	InstallOnly  bool                  `mapstructure:"install_only"`
	SkipCommands map[string][]string   `mapstructure:"skip_commands"`
	Server       ProxyServerConfig     `mapstructure:"server"`
	Registries   []ProxyRegistryConfig `mapstructure:"registries"`
}

// ProxyServerConfig configures the persistent proxy server (`pmg proxy start`).
type ProxyServerConfig struct {
	// ListenHost is the host the persistent proxy binds to. Defaults to
	// 127.0.0.1 (loopback). Set to 0.0.0.0 or a specific interface only for a
	// deliberately hosted deployment: a non-loopback bind exposes the MITM
	// proxy to the network. The --host flag overrides this.
	ListenHost string `mapstructure:"listen_host"`

	// ListenPort is the port the persistent proxy binds to. 0 (default) means a
	// random free port. The --port flag overrides this.
	ListenPort int `mapstructure:"listen_port"`

	// Profile names the sandbox profile whose network rules the proxy
	// applies: a built-in name, a policy_templates name, a user profile
	// name, or a path. A relative path resolves against the config
	// directory. Empty means no policy. The --profile flag overrides this.
	Profile string `mapstructure:"profile"`

	// NetworkMode is audit or enforce, as sandbox.network_mode. The
	// --network-mode flag overrides this.
	NetworkMode string `mapstructure:"network_mode"`

	// Enforce makes the Linux kernel route the connections of every eligible
	// process to the proxy, so a process cannot opt out through its
	// environment. See docs/persistent-proxy.md.
	Enforce ProxyEnforceConfig `mapstructure:"enforce"`
}

// ProxyEnforceConfig is the eligibility policy for kernel enforcement. Users
// describe it in terms they know in advance: ports, users and executable
// paths. The daemon itself is always exempt. Nothing else is.
type ProxyEnforceConfig struct {
	// Enabled turns enforcement on. The --enforce flag overrides this.
	Enabled bool `mapstructure:"enabled"`

	// Ports are the destination ports the kernel routes. The ports of
	// proxy.registries endpoints are always added.
	Ports []int `mapstructure:"ports"`

	// EligibleUsers narrows enforcement to these users. Empty means every
	// user. Unsafe when an eligible user has sudo.
	EligibleUsers []string `mapstructure:"eligible_users"`

	// ExemptUsers are never routed.
	ExemptUsers []string `mapstructure:"exempt_users"`

	// ExemptExecutables are absolute paths or globs of programs that connect
	// directly, such as a CI runner agent.
	ExemptExecutables []string `mapstructure:"exempt_executables"`

	// SkipDestinations are CIDR prefixes added to the built-in skip list.
	SkipDestinations []string `mapstructure:"skip_destinations"`

	// Cgroup is the cgroup v2 directory to attach to. Empty means the root.
	Cgroup string `mapstructure:"cgroup"`

	// DenyUDP denies UDP to the routed ports, so QUIC falls back to TCP.
	DenyUDP bool `mapstructure:"deny_udp"`

	// Namespaces says what happens to a socket in another network
	// namespace, such as a container's. See docs/persistent-proxy.md.
	Namespaces ProxyEnforceNamespacesConfig `mapstructure:"namespaces"`
}

// ProxyEnforceNamespacesConfig is the redirect for other network
// namespaces. Their traffic enters the host through a bridge, where an
// nftables rule sends the enforced ports to the proxy.
type ProxyEnforceNamespacesConfig struct {
	// Mode is ignore, redirect or auto. redirect fails the start when the
	// host cannot redirect. auto falls back to ignore and says why.
	Mode string `mapstructure:"mode"`

	// Ingress names the interfaces whose incoming traffic is redirected. A
	// trailing * matches a prefix. The default covers Docker's networks.
	Ingress []string `mapstructure:"ingress"`

	// Address is the IPv4 address the daemon adds to lo and listens on.
	Address string `mapstructure:"address"`
}

const (
	// SandboxNetworkModeAudit makes the proxy record what the network rules
	// would deny and deny nothing.
	SandboxNetworkModeAudit = "audit"

	// SandboxNetworkModeEnforce makes the proxy deny what the network rules
	// deny.
	SandboxNetworkModeEnforce = "enforce"
)

const (
	sandboxNetworkModeKey     = "sandbox.network_mode"
	proxyServerNetworkModeKey = "proxy.server.network_mode"
)

// NetworkModeError reports a network mode value that is not audit or
// enforce. It fails the config load closed, because a mode pmg cannot read
// must not run as the weaker one.
type NetworkModeError struct {
	Key  string
	Mode string
}

func (e *NetworkModeError) Error() string {
	return fmt.Sprintf("invalid %s %q (expected %s or %s)", e.Key, e.Mode, SandboxNetworkModeAudit, SandboxNetworkModeEnforce)
}

// ValidateSandboxNetworkMode checks a sandbox.network_mode value. An empty
// value is the default, audit.
func ValidateSandboxNetworkMode(mode string) error {
	return validateNetworkMode(sandboxNetworkModeKey, mode)
}

// ValidateProxyServerNetworkMode checks a proxy.server.network_mode value.
func ValidateProxyServerNetworkMode(mode string) error {
	return validateNetworkMode(proxyServerNetworkModeKey, mode)
}

func validateNetworkMode(key, mode string) error {
	switch mode {
	case "", SandboxNetworkModeAudit, SandboxNetworkModeEnforce:
		return nil
	}
	return &NetworkModeError{Key: key, Mode: mode}
}

// SandboxConfig configures the sandbox system for isolating package manager processes.
type SandboxConfig struct {
	// Enabled enables sandbox mode (opt-in by default for backward compatibility).
	Enabled bool `mapstructure:"enabled"`

	// EnforceAlways controls scope of sandbox enforcement:
	// - When true: sandbox applies to all package manager commands
	// - When false: sandbox only applies to install commands, others run unrestricted (default)
	EnforceAlways bool `mapstructure:"enforce_always"`

	// NetworkMode is the posture of the PMG proxy for the network rules of
	// the sandbox profile: audit records what the rules would deny and
	// denies nothing, enforce denies it. The mode lives here and not in the
	// profile, because one profile can run in audit on one host and in
	// enforce on another.
	NetworkMode string `mapstructure:"network_mode"`

	// Policies maps package manager names to their sandbox policy references.
	// Key is package manager name (e.g., "npm", "pip"), value is policy reference.
	Policies map[string]SandboxPolicyRef `mapstructure:"policies"`

	// PolicyTemplates maps template names to their paths.
	PolicyTemplates map[string]SandboxPolicyTemplate `mapstructure:"policy_templates"`
}

// DependencyCooldownConfig blocks installation of package versions published within a
// configurable time window, reducing exposure to supply chain attacks.
type DependencyCooldownConfig struct {
	Enabled bool `mapstructure:"enabled"`
	Days    int  `mapstructure:"days"`

	// Skip is a per-control skip list of packages exempt from the cooldown
	// window. Unlike the top-level trusted_packages (which waives every PMG
	// control — malware analysis, cooldown, and any future controls — and is
	// already honored here), an entry on this list waives ONLY the cooldown
	// wait, never malware analysis, so a fast-tracked package is still
	// scanned. Intended for first-party / internal packages that must be
	// installed immediately on release.
	//
	// Matching: a PURL without a version skips cooldown for ALL versions of the
	// package (package-level); a PURL with a version skips cooldown for that
	// version only (version-level).
	Skip []TrustedPackage `mapstructure:"skip"`
}

// legacyProfileAliases maps old default profile names, keyed by package
// manager, to their per-PM leaf profiles. When npm-restrictive and
// pypi-restrictive became pure bases with no environment allows (and
// pnpm-restrictive was renamed to pnpm), existing config files kept the old
// mappings (config merge preserves user values), so the old defaults are
// re-mapped at read time.
var legacyProfileAliases = map[string]map[string]string{
	"npm-restrictive": {
		"npm":  "npm",
		"yarn": "yarn",
		"bun":  "bun",
	},
	"pnpm-restrictive": {
		"pnpm": "pnpm",
	},
	// pnpx mapped to the npx profile until pnpx got its own leaf with the
	// corepack cache. npx keeps the npx profile.
	"npx": {
		"pnpx": "pnpx",
	},
	"pypi-restrictive": {
		"pip":    "pip",
		"pip3":   "pip",
		"pipx":   "pipx",
		"poetry": "poetry",
		"uv":     "uv",
		"uvx":    "uvx",
	},
}

// PolicyFor returns the sandbox policy reference for a package manager,
// re-mapping legacy default profiles to their per-PM leaf profiles. The
// re-mapping is skipped when a policy template overrides the legacy name,
// since the user's custom template must keep winning as it did before the
// profile split.
func (s *SandboxConfig) PolicyFor(pmName string) (SandboxPolicyRef, bool) {
	ref, exists := s.Policies[pmName]
	if !exists {
		return SandboxPolicyRef{}, false
	}

	if leaves, legacy := legacyProfileAliases[ref.Profile]; legacy {
		if _, overridden := s.PolicyTemplates[ref.Profile]; !overridden {
			if leaf, ok := leaves[pmName]; ok {
				ref.Profile = leaf
			}
		}
	}

	return ref, true
}

// SandboxPolicyTemplate defines a template for a sandbox policy, used to map
// a profile name to a path.
type SandboxPolicyTemplate struct {
	// Path is the path to the template file.
	// Relative path can be used to reference a template file in the config directory (example: ./npm-restrictive.yml)
	Path string `mapstructure:"path"`
}

// SandboxPolicyRef references a sandbox policy for a specific package manager.
type SandboxPolicyRef struct {
	// Enabled enables sandboxing for this specific package manager.
	Enabled bool `mapstructure:"enabled"`

	// Profile is the name of a built-in profile (e.g., "npm-restrictive")
	// or an absolute path to a custom YAML policy file.
	Profile string `mapstructure:"profile"`
}

// TrustedPackage is a package that is trusted by the user and will be ignored by the security guardrails.
type TrustedPackage struct {
	Purl   string `mapstructure:"purl"`
	Reason string `mapstructure:"reason"`

	purlRef
}

// RuntimeConfig is the configuration that is used at runtime. It contains static configuration
// that can be loaded from a source and, if allowed, overridden by the user at runtime.
type RuntimeConfig struct {
	Config Config

	// DryRun enables dry-run mode for the package manager, where actual execution of commands is skipped.
	DryRun bool

	// InsecureInstallation allows bypassing install blocking on malicious packages
	InsecureInstallation bool

	// SandboxProfileOverride is a runtime override for the sandbox policy profile.
	// When set, this profile path is used instead of the configured policy for all package managers.
	// This is a CLI-only flag (--sandbox-profile) and is not persisted to config.yml.
	SandboxProfileOverride string

	// SandboxAllowOverrides holds runtime sandbox allow rules from --sandbox-allow flags.
	// These are additive rules applied on top of the resolved sandbox policy.
	// Not persisted to config.yml.
	SandboxAllowOverrides []SandboxAllowOverride

	// SandboxNetworkAllow and SandboxNetworkDeny are the rules from the
	// --network-allow and --network-deny flags of pmg sandbox exec. Each
	// adds to the network block of the resolved policy. Not persisted.
	SandboxNetworkAllow []string
	SandboxNetworkDeny  []string

	// Internal config values computed at runtime and must be accessed via. API
	configDir                string
	configFilePath           string // active config: globally managed file if present, else per-user
	userConfigFilePath       string // per-user config file, used for writes and removal
	configSource             ConfigSource
	configLocked             bool  // global file present and opted into lockdown (global_lockdown: true)
	managedConfigErr         error // why PMG ignores a managed config file that is present
	eventLogDir              string
	sandboxProfileDir        string
	sandboxOverlayDir        string
	sandboxPresetDir         string
	sandboxViolationCacheDir string
	localDBDir               string
	cacheDir                 string
	viper                    *viper.Viper
}

// CloudSyncDBPath returns the path to the cloud sync WAL database.
func (r *RuntimeConfig) CloudSyncDBPath() string {
	return filepath.Join(r.configDir, "cloud-sync.db")
}

// CloudSyncLockPath returns the path to the cross-process lock file that
// serializes manual `pmg cloud sync` and the auto-sync background child.
func (r *RuntimeConfig) CloudSyncLockPath() string {
	return filepath.Join(r.configDir, "cloud-sync.lock")
}

// CloudSyncLastRunPath returns the path to the timestamp file recording the
// last sync attempt (success or failure) in Unix epoch seconds.
func (r *RuntimeConfig) CloudSyncLastRunPath() string {
	return filepath.Join(r.configDir, "cloud-sync.lastrun")
}

// CloudCheckInLastRunPath returns the path to the timestamp file recording
// the last check-in attempt (success or failure) in Unix epoch seconds.
func (r *RuntimeConfig) CloudCheckInLastRunPath() string {
	return filepath.Join(r.configDir, "cloud-checkin.lastrun")
}

// ConfigFilePath returns the path to the active config file (the globally
// managed file when present, otherwise the per-user file).
func (r *RuntimeConfig) ConfigFilePath() string {
	return r.configFilePath
}

// ConfigSource names where the active config file came from. A root daemon
// reads a different file than the user who started it edits, and the label
// is how status and `pmg config path` make that visible.
type ConfigSource string

const (
	// ConfigSourceManaged is the globally managed file, authoritative for
	// every user.
	ConfigSourceManaged ConfigSource = "managed"
	// ConfigSourceEnvDir is the file under PMG_CONFIG_DIR.
	ConfigSourceEnvDir ConfigSource = "PMG_CONFIG_DIR"
	// ConfigSourceRootPerUser is root's own per-user file, read under sudo.
	ConfigSourceRootPerUser ConfigSource = "root per-user"
	// ConfigSourceUser is the per-user file of the account that runs pmg.
	ConfigSourceUser ConfigSource = "user"
)

// ConfigSource reports where the active config file came from.
func (r *RuntimeConfig) ConfigSource() ConfigSource {
	return r.configSource
}

// RootUserConfigFilePath returns the per-user config file of root, the one
// a daemon started with sudo reads when no managed config exists. It fails
// where root has no passwd entry.
func RootUserConfigFilePath() (string, error) {
	home, err := rootHomeDirResolver()
	if err != nil {
		return "", err
	}
	return filepath.Join(platform.HomeDirs(home).Config, pmgDefaultHomeRelativePath, pmgConfigFileName), nil
}

func resolveConfigSource(managed bool) ConfigSource {
	switch {
	case managed:
		return ConfigSourceManaged
	case os.Getenv(pmgConfigDirEnvKey) != "":
		return ConfigSourceEnvDir
	default:
		if _, ok := sudoRootHome(); ok {
			return ConfigSourceRootPerUser
		}
		return ConfigSourceUser
	}
}

// UserConfigFilePath returns the per-user config file path, regardless of
// whether a globally managed config is active.
func (r *RuntimeConfig) UserConfigFilePath() string {
	return r.userConfigFilePath
}

// IsManaged reports whether the active config is the globally managed file.
// When true, the per-user file is ignored and config writes are refused. It is
// derived: the active path differs from the per-user path only when the global
// file was chosen.
func (r *RuntimeConfig) IsManaged() bool {
	return r.configFilePath != r.userConfigFilePath
}

// IsLocked reports whether a globally managed config opted into lockdown via
// global_lockdown: true. When locked, env and CLI overrides of config are
// refused. An unlocked managed config is an overridable baseline: it stays the
// authoritative file (the per-user file is still ignored), but env and CLI args
// can override its values at runtime.
func (r *RuntimeConfig) IsLocked() bool {
	return r.configLocked
}

// ManagedConfigError returns why PMG ignores the managed config file that is
// present, or nil. Package init resolves the config before the CLI sets up
// any output, so the CLI must report this error itself.
func (r *RuntimeConfig) ManagedConfigError() error {
	return r.managedConfigErr
}

// ManagedConfigWarning returns the text that tells the user why PMG ignores
// the managed config, or "" when PMG obeys it or no file is present.
func (r *RuntimeConfig) ManagedConfigWarning() string {
	err := r.managedConfigErr
	if err == nil {
		return ""
	}
	usefulErr, ok := usefulerror.AsUsefulError(err)
	if !ok {
		return err.Error()
	}
	return fmt.Sprintf("%s: %v. %s", usefulErr.HumanError(), err, usefulErr.Help())
}

// EventLogDir returns the path to the event log directory.
func (r *RuntimeConfig) EventLogDir() string {
	return r.eventLogDir
}

// ConfigDir returns the path to the config directory.
func (r *RuntimeConfig) ConfigDir() string {
	return r.configDir
}

// SandboxProfileDir returns the path to the user sandbox profile directory.
func (r *RuntimeConfig) SandboxProfileDir() string {
	return r.sandboxProfileDir
}

// SandboxPolicyTemplatePaths returns the policy templates of the config as
// template name to file path. A relative path is next to the config file
// that declares it. For a managed config that is the managed directory and
// not the user's, so a locked template cannot point into a directory the
// user writes.
func (r *RuntimeConfig) SandboxPolicyTemplatePaths() map[string]string {
	paths := make(map[string]string, len(r.Config.Sandbox.PolicyTemplates))
	for name, template := range r.Config.Sandbox.PolicyTemplates {
		path := template.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(r.configFilePath), path)
		}
		paths[name] = path
	}
	return paths
}

// SandboxOverlayDir returns the path to the per-repo sandbox overlay directory.
func (r *RuntimeConfig) SandboxOverlayDir() string {
	return r.sandboxOverlayDir
}

// SandboxPresetDir returns the path to the user sandbox preset directory.
func (r *RuntimeConfig) SandboxPresetDir() string {
	return r.sandboxPresetDir
}

// SandboxViolationCacheDir returns the path to the sandbox violation cache directory.
func (r *RuntimeConfig) SandboxViolationCacheDir() string {
	return r.sandboxViolationCacheDir
}

// CacheDir returns the path to the PMG cache root directory. This follows the
// platform cache convention (XDG cache dir on Linux, ~/Library/Caches on macOS,
// %LOCALAPPDATA% on Windows) and is overridable via PMG_CACHE_DIR. Caching
// layers (e.g. the analysis cache) should store regenerable data here rather
// than under the config directory.
func (r *RuntimeConfig) CacheDir() string {
	return r.cacheDir
}

// LocalDBDir returns the directory holding PMG's shared localdb SQLite file.
// localdb writes sibling -wal/-shm files here, so the Dir and FileName are
// exposed separately to match localdb.Config rather than as a joined path.
func (r *RuntimeConfig) LocalDBDir() string {
	return r.localDBDir
}

// LocalDBFileName returns the file name of PMG's shared localdb SQLite file.
func (r *RuntimeConfig) LocalDBFileName() string {
	return pmgDefaultLocalDBFileName
}

// SandboxAllowType represents the type of a sandbox allow override.
type SandboxAllowType string

const (
	SandboxAllowRead       SandboxAllowType = "read"
	SandboxAllowWrite      SandboxAllowType = "write"
	SandboxAllowExec       SandboxAllowType = "exec"
	SandboxAllowNetConnect SandboxAllowType = "net-connect"
	SandboxAllowNetBind    SandboxAllowType = "net-bind"
	SandboxAllowEnv        SandboxAllowType = "env"
	SandboxAllowPreset     SandboxAllowType = "preset"
)

// SandboxAllowOverride represents a single --sandbox-allow flag value.
type SandboxAllowOverride struct {
	// Type is the resource type (read, write, exec, net-connect, net-bind,
	// env, preset).
	Type SandboxAllowType

	// Value is the resolved value (absolute path, host:port, etc.).
	Value string

	// Raw is the original CLI value before resolution (for logging/warnings).
	Raw string
}

// DefaultConfig is a fail safe contract for the runtime configuration.
// The config package return an appropriate RuntimeConfig based on the environment and the configuration.
func DefaultConfig() RuntimeConfig {
	// Backward compatibility for the insecure installation flag before config was introduced.
	insecureInstallation := utils.EnvBool(pmgInsecureInstallationEnvKey, false)

	return RuntimeConfig{
		Config: Config{
			Paranoid:              false,
			DisableTelemetry:      false,
			EventLogRetentionDays: 7,
			SkipEventLogging:      false,
			TrustedPackages:       []TrustedPackage{},
			AdvisoryMessage:       "",
			Verbosity:             VerbosityNormal,
			Sandbox: SandboxConfig{
				Enabled:       false,
				EnforceAlways: false,
				NetworkMode:   SandboxNetworkModeAudit,
			},
			DependencyCooldown: DependencyCooldownConfig{
				Enabled: true,
				Days:    2,
			},
			AnalysisCache: AnalysisCacheConfig{
				Malysis: MalysisCacheConfig{
					Enabled: false,
					TTL:     24 * time.Hour,
				},
			},
			Cloud: CloudConfig{
				Enabled: false,
				AutoSync: CloudAutoSyncConfig{
					Enabled:     true,
					MinInterval: 15 * time.Minute,
					Timeout:     5 * time.Minute,
				},
			},
			Proxy: ProxyConfig{
				InstallOnly:  false,
				SkipCommands: map[string][]string{},
				Server: ProxyServerConfig{
					ListenHost:  "127.0.0.1",
					NetworkMode: SandboxNetworkModeAudit,
					Enforce: ProxyEnforceConfig{
						Ports:   []int{80, 443},
						DenyUDP: true,
					},
				},
			},
		},
		DryRun:               false,
		InsecureInstallation: insecureInstallation,
	}
}

// globalConfig is the global configuration for PMG.
// It is initialized in the init function and can be overridden by a repository.
var globalConfig *RuntimeConfig

func init() {
	initConfig()
}

// Reload re-runs the initialization that runs at package init. Tests that
// mutate PMG_CONFIG_DIR via t.Setenv must call this so the resolved config
// directory reflects the new env, instead of the value computed when the
// package was first loaded.
func Reload() {
	initConfig()
}

// initConfig should be idempotent and can be called multiple times.
// This is required for testing purposes.
func initConfig() {
	defaultConfig := DefaultConfig()
	globalConfig = &defaultConfig

	configInitErr = globalConfig.resolvePaths()

	// A globally managed config enforces lockdown only when it opts in via
	// global_lockdown, read straight from the file so it cannot be flipped by
	// env or CLI.
	globalConfig.configLocked = globalConfig.IsManaged() && globalConfigEnablesLockdown(globalConfigFilePath())
	sandboxutil.IgnoreXDGEnvironment(globalConfig.IsLocked())

	// When locked, env cannot bypass the config, including the
	// PMG_INSECURE_INSTALLATION malicious-package block bypass.
	if globalConfig.IsLocked() {
		globalConfig.InsecureInstallation = false
	}

	configLoadErr = loadConfig()

	if err := preprocessPackageRefs(&globalConfig.Config); err != nil {
		log.Warnf("Failed to preprocess package refs: %v", err)
	}
}

// resolvePaths sets the per-user paths. A path that does not resolve stays
// empty and resolvePaths returns the error, so a managed config still loads.
func (r *RuntimeConfig) resolvePaths() error {
	configDir, configErr := configDir()
	if configErr == nil {
		r.configDir = configDir
		r.userConfigFilePath = filepath.Join(configDir, pmgConfigFileName)
		r.sandboxProfileDir = filepath.Join(configDir, pmgDefaultSandboxProfileDir)
		r.sandboxOverlayDir = filepath.Join(configDir, pmgDefaultSandboxOverlayDir)
		r.sandboxPresetDir = filepath.Join(configDir, pmgDefaultSandboxPresetDir)
	}

	cacheDir, cacheErr := cacheDir()
	if cacheErr == nil {
		r.cacheDir = cacheDir
		r.sandboxViolationCacheDir = filepath.Join(cacheDir, pmgDefaultSandboxViolationCacheDir)
		r.localDBDir = filepath.Join(cacheDir, pmgDefaultLocalDBDir)
	}

	// Where the config directory roams with the profile, the logs go beside
	// the data instead: https://github.com/safedep/pmg/pull/82#discussion_r2636746036
	// PMG_CONFIG_DIR names no roaming directory, so the logs stay under it.
	logBaseDir, logErr := configDir, configErr
	if platform.UserConfigDirRoams && os.Getenv(pmgConfigDirEnvKey) == "" {
		logBaseDir, logErr = UserDataDir()
	}
	if logErr == nil {
		r.eventLogDir = filepath.Join(logBaseDir, pmgDefaultLogDir)
	}

	managed, managedErr := managedConfigFile()
	r.managedConfigErr = managedErr
	r.configFilePath = r.userConfigFilePath
	if managed != "" {
		r.configFilePath = managed
	}
	r.configSource = resolveConfigSource(managed != "")

	return cmp.Or(configErr, cacheErr, logErr)
}

// configInitErr holds the error from the last resolvePaths call, if any,
// exposed via InitError.
var configInitErr error

// InitError returns the error that left the per-user paths unresolved, or
// nil. The CLI must abort on it before a command uses those paths.
func InitError() error {
	return configInitErr
}

// configLoadErr holds the fail-closed error from the last loadConfig call,
// if any, exposed via LoadError so the CLI can abort before running.
var configLoadErr error

// LoadError returns the error that made configuration loading fail closed,
// or nil. An invalid proxy.registries entry and an invalid
// sandbox.network_mode set this, since falling back to defaults would
// silently drop a protection the user configured; every other load failure
// still warns and continues.
func LoadError() error {
	return configLoadErr
}

// NewInvalidNetworkModeError turns a NetworkModeError into the error the
// CLI reports.
func NewInvalidNetworkModeError(err *NetworkModeError) error {
	return usefulerror.NewUsefulError().
		WithCode(errcodes.InvalidArgument).
		WithHumanError(err.Error()).
		WithHelp(fmt.Sprintf("Set %s to audit or enforce in your PMG configuration file, then retry.", err.Key)).
		Wrap(err)
}

func NewInvalidProxyRegistriesError(err error) error {
	detail := err
	var registriesErr *ProxyRegistriesError
	if errors.As(err, &registriesErr) {
		detail = registriesErr.Unwrap()
	}

	return usefulerror.NewUsefulError().
		WithCode(errcodes.InvalidProxyRegistries).
		WithHumanError(fmt.Sprintf("invalid proxy registries configuration: %v", detail)).
		WithHelp("Fix the proxy.registries entries in your PMG configuration file, then retry.").
		Wrap(err)
}

// NewGoProxyConflictError turns a GoProxyConflictError into the error that
// `pmg go` reports.
func NewGoProxyConflictError(err *GoProxyConflictError) error {
	return usefulerror.NewUsefulError().
		WithCode(errcodes.InvalidProxyRegistries).
		WithHumanError(err.Error()).
		WithHelp("Use a GOPROXY base path that does not nest with the base path of that registry endpoint, or remove the entry from GOPROXY.").
		Wrap(err)
}

// loadConfig loads the configuration from the config file.
// This is where we determine the source of config and use the appropriate loader.
// Right now we only support loading from a config file using Viper. An
// invalid proxy.registries entry fails closed, since falling back to
// defaults would silently drop the configured protection. Every other
// load failure falls back to defaults with a warning.
func loadConfig() error {
	err := loadViperConfig()
	if err == nil {
		return nil
	}

	var registriesErr *ProxyRegistriesError
	if errors.As(err, &registriesErr) {
		return NewInvalidProxyRegistriesError(err)
	}

	var modeErr *NetworkModeError
	if errors.As(err, &modeErr) {
		return NewInvalidNetworkModeError(modeErr)
	}

	log.Warnf("Failed to load config, using defaults: %v", err)
	return nil
}

// rootHomeDir returns root's home from the passwd database. Path resolution
// for root must not consult HOME or XDG_*: sudo and su can preserve the
// invoking user's environment (GitHub runners, sudo -E, su without -), which
// would make root create root-owned state inside that user's home and
// fail-close every later non-root pmg run for them.
func rootHomeDir() (string, error) {
	u, err := user.LookupId("0")
	if err != nil {
		return "", fmt.Errorf("failed to resolve root home directory: %w", err)
	}
	if u.HomeDir == "" {
		return "", fmt.Errorf("root user has no home directory")
	}
	return u.HomeDir, nil
}

// sudoRootHome returns root's passwd home when pmg runs as root through
// sudo. Without a resolvable root passwd entry (scratch containers, minimal
// chroots) it reports false and the caller resolves from the environment:
// without a passwd database there is no user switching, so the cross-user
// poisoning the diversion prevents cannot occur.
func sudoRootHome() (string, bool) {
	if !platform.IsSudo() {
		return "", false
	}
	home, err := rootHomeDirResolver()
	if err != nil {
		log.Warnf("failed to resolve root home, using environment: %v", err)
		return "", false
	}
	return home, true
}

// userBaseDir resolves a base directory of the user pmg runs as. Under sudo,
// root's passwd home wins over a HOME preserved from the invoking user, so an
// elevated run never reads or writes that user's dotfiles. Otherwise fromEnv
// reads the environment. When fromEnv fails, the directory derives from the
// home that platform.UserHomeDir resolves. That covers an invalid XDG_*
// value, and a systemd unit without User= that sets no HOME.
func userBaseDir(fromEnv func() (string, error), fromHome func(home string) string) (string, error) {
	if home, ok := sudoRootHome(); ok {
		return fromHome(home), nil
	}

	dir, envErr := fromEnv()
	if envErr == nil {
		return dir, nil
	}

	home, err := platform.UserHomeDir()
	if err != nil {
		return "", newUnresolvedUserDirError(errors.Join(envErr, err))
	}
	return fromHome(home), nil
}

func newUnresolvedUserDirError(err error) error {
	return usefulerror.NewUsefulError().
		WithCode(errcodes.UserDirUnresolved).
		WithHumanError("failed to find the home directory of the current user").
		WithHelp(fmt.Sprintf("Set %s, or set %s and %s, then retry.", platform.UserDirEnvVars(), pmgConfigDirEnvKey, pmgCacheDirEnvKey)).
		Wrap(err)
}

// pmgUserDir returns pmg's directory under one base directory of the user.
// A non-empty value of the overrideEnvKey variable wins.
func pmgUserDir(overrideEnvKey string, fromEnv func() (string, error), pick func(platform.Dirs) string) (string, error) {
	if overrideEnvKey != "" {
		if dir := os.Getenv(overrideEnvKey); dir != "" {
			return dir, nil
		}
	}

	base, err := userBaseDir(fromEnv, func(home string) string { return pick(platform.HomeDirs(home)) })
	if err != nil {
		return "", err
	}
	return filepath.Join(base, pmgDefaultHomeRelativePath), nil
}

// UserHomeDir returns the home directory pmg should treat as the current
// user's, with the same resolution as the config directory. Callers resolving
// paths that sit alongside the config directory must use this rather than
// os.UserHomeDir, otherwise the two can disagree under sudo.
func UserHomeDir() (string, error) {
	return userBaseDir(os.UserHomeDir, func(home string) string { return home })
}

// Overridable in tests to exercise the passwd-unavailable fallback.
var rootHomeDirResolver = rootHomeDir

// unwritableDirCause is why the current user cannot write a per-user
// directory. The remedy must match the cause: chown-ing a directory that
// belongs to another account steals it and breaks that account, so chown is
// only safe for a directory inside the current user's passwd home, which a
// leaked environment cannot influence.
type unwritableDirCause int

const (
	// causeExplicitConfigDir: PMG_CONFIG_DIR selected the directory.
	causeExplicitConfigDir unwritableDirCause = iota
	// causeLeakedHomeEnv: the directory is outside the current user's passwd
	// home, so HOME or XDG_CONFIG_HOME leaked from another account (e.g.
	// sudo -u on hosts that preserve the environment).
	causeLeakedHomeEnv
	// causeRootCreatedDir: the directory is inside the user's own home; a
	// root or sudo run most likely created it root-owned.
	causeRootCreatedDir
)

func classifyUnwritableDir(dir string) unwritableDirCause {
	if os.Getenv(pmgConfigDirEnvKey) != "" {
		return causeExplicitConfigDir
	}

	home, err := platform.PasswdHomeDir()
	if err == nil && !fsutil.PathWithinDir(dir, home) {
		return causeLeakedHomeEnv
	}

	return causeRootCreatedDir
}

// UnwritableConfigDirRemedy renders the remedy for a per-user config or
// event-log directory the current user cannot write: help is the full
// explanation for fatal CLI errors, fix the terse variant for the doctor
// table. Cause diagnosis lives in classifyUnwritableDir.
func UnwritableConfigDirRemedy(dir string) (help, fix string) {
	switch classifyUnwritableDir(dir) {
	case causeExplicitConfigDir:
		return fmt.Sprintf("PMG_CONFIG_DIR points at %s; make it writable by your user", dir),
			"Make PMG_CONFIG_DIR writable"
	case causeLeakedHomeEnv:
		return platform.LeakedConfigDirRemedy(dir)
	default:
		return platform.OwnershipRestoreRemedy(dir)
	}
}

func pickConfig(d platform.Dirs) string { return d.Config }
func pickCache(d platform.Dirs) string  { return d.Cache }
func pickData(d platform.Dirs) string   { return d.Data }

// configDir computes the path to the config directory.
func configDir() (string, error) {
	return pmgUserDir(pmgConfigDirEnvKey, os.UserConfigDir, pickConfig)
}

// cacheDir computes the path to the cache root directory.
func cacheDir() (string, error) {
	return pmgUserDir(pmgCacheDirEnvKey, platform.UserCacheDir, pickCache)
}

// UserDataDir returns the per-user directory for pmg data that is neither
// config nor regenerable cache, such as the shim scripts installed by
// `pmg setup install`. Linux follows XDG_DATA_HOME; macOS and Windows have no
// separate data location, so they reuse the config convention.
func UserDataDir() (string, error) {
	return pmgUserDir("", platform.UserDataDir, pickData)
}

// userConfigFilePath computes the path to the per-user config file.
func userConfigFilePath() (string, error) {
	configDir, err := configDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(configDir, pmgConfigFileName), nil
}

// globalConfigDirOverride replaces the OS-level managed config directory. It
// exists only for tests within this package. There is intentionally no env var
// or flag for it, so a user cannot point the "managed" config at their own file
// and bypass the globally managed config.
var globalConfigDirOverride string

func globalConfigDir() string {
	if globalConfigDirOverride != "" {
		return globalConfigDirOverride
	}
	return platform.SystemConfigDir()
}

// SetManagedConfigDirForTest points the managed config lookup at dir and
// reloads, so a test in another package can run under a locked config. It
// panics outside a test binary, so it cannot move the managed boundary in
// production. The returned function restores the real directory.
func SetManagedConfigDirForTest(dir string) (restore func()) {
	if !testing.Testing() {
		panic("config: SetManagedConfigDirForTest called outside a test")
	}
	globalConfigDirOverride = dir
	initConfig()
	return func() {
		globalConfigDirOverride = ""
		initConfig()
	}
}

// LockedRuntimeConfigForTest returns a config that reports lockdown, so a
// test in another package can check what a command refuses under it. It
// panics outside a test binary.
func LockedRuntimeConfigForTest() *RuntimeConfig {
	if !testing.Testing() {
		panic("config: LockedRuntimeConfigForTest called outside a test")
	}
	return &RuntimeConfig{configLocked: true}
}

// globalConfigFilePath returns the path to the globally managed config file, or
// "" when the platform has no global config location.
func globalConfigFilePath() string {
	dir := globalConfigDir()
	if dir == "" {
		return ""
	}

	return filepath.Join(dir, pmgConfigFileName)
}

// managedConfigFile returns the globally managed config file when it is
// present and trusted. That file is authoritative, and the per-user file is
// then ignored entirely. It returns "" and nil when no file is present. It
// returns "" and the reason when PMG ignores a file that is present, so the
// CLI can tell the user that the managed policy does not apply.
func managedConfigFile() (string, error) {
	global := globalConfigFilePath()
	if global == "" {
		return "", nil
	}
	if _, err := os.Lstat(global); errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err := requireSystemControlledConfig(global); err != nil {
		return "", err
	}
	return global, nil
}

// requireSystemControlledConfig checks that only a system account controls
// the managed config. The file governs every account, so PMG obeys it only
// when a system account owns the file and both directories above it, and no
// other account may write any of the three. The system account is root on
// Unix, and Administrators or SYSTEM on Windows. On Windows, ProgramData
// lets any user create a directory or a file at the managed path. On Unix,
// the check of each path also covers every directory above it.
func requireSystemControlledConfig(path string) error {
	if err := requireManagedConfigDirs(path); err != nil {
		return err
	}
	if err := platform.RequireSystemControlled(path); err != nil {
		return untrustedManagedConfigError(path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return untrustedManagedConfigError(path, err)
	}
	if !info.Mode().IsRegular() {
		return untrustedManagedConfigError(path, fmt.Errorf("%s is not a regular file", path))
	}
	return nil
}

// requireSystemControlledBeforeWrite checks the directories of the managed
// config, and the file when it exists, before the install writes or merges
// it.
func requireSystemControlledBeforeWrite(path string) error {
	if err := requireManagedConfigDirs(path); err != nil {
		return err
	}
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return untrustedManagedConfigError(path, err)
	}
	return requireSystemControlledConfig(path)
}

// requireManagedConfigDirs checks the two directories above the managed
// config. Only the system account may create an entry in them, also when they
// are sticky, so no other account can create the file after a check.
func requireManagedConfigDirs(path string) error {
	dir := filepath.Dir(path)
	for _, p := range []string{filepath.Dir(dir), dir} {
		if err := platform.RequireSystemControlled(p); err != nil {
			return untrustedManagedConfigError(path, err)
		}
		if err := platform.RequireExclusiveSystemDir(p); err != nil {
			return untrustedManagedConfigError(path, err)
		}
	}
	return nil
}

func untrustedManagedConfigError(path string, err error) error {
	return usefulerror.NewUsefulError().
		WithCode(errcodes.PermissionDenied).
		WithHumanError(fmt.Sprintf("The managed config %s does not apply, because an account other than the system account can change it", path)).
		WithHelp(platform.SystemControlRemedy(path)).
		Wrap(err)
}

// Get returns the global configuration.
// This is the public API for the configuration package. This package should guarantee
// that this function will never return nil.
func Get() *RuntimeConfig {
	return globalConfig
}

// AdvisoryMessage returns the org-configured advisory message appended to
// policy block output. Empty when not configured.
func AdvisoryMessage() string {
	return globalConfig.Config.AdvisoryMessage
}

func ConfigureSandbox(mayDownloadPackages bool) {
	if globalConfig.Config.Sandbox.Enabled {
		// Apply sandbox to all commands if EnforceAlways=true, otherwise only to
		// commands that may download packages (install, update, etc.)
		globalConfig.Config.Sandbox.Enabled = globalConfig.Config.Sandbox.EnforceAlways || mayDownloadPackages
	}
}

// WriteTemplateConfig writes the template configuration file to disk.
// If the config file does not exist, the full template is written.
// If it already exists, missing keys from the template are merged
// into the existing config while preserving all user values and comments.
//
// When a globally managed config is active, this is a no-op: the per-user
// file is ignored at load time, so creating it would only mislead.
func WriteTemplateConfig() error {
	if globalConfig.IsManaged() {
		return nil
	}

	configFilePath, err := userConfigFilePath()
	if err != nil {
		return fmt.Errorf("failed to get config file path: %w", err)
	}

	return writeTemplateConfigFile(configFilePath)
}

// RemoveUserConfigFile deletes the per-user config file. It never touches the
// globally managed file. A missing file is not an error.
func RemoveUserConfigFile() error {
	path, err := userConfigFilePath()
	if err != nil {
		return fmt.Errorf("failed to get config file path: %w", err)
	}

	return removeFileIfExists(path)
}

// WriteSystemTemplateConfig writes the template configuration to the OS-level
// managed config path (e.g. /etc/safedep/pmg/config.yml on Linux). Used by
// `pmg setup install --system`.
func WriteSystemTemplateConfig() error {
	path := globalConfigFilePath()
	if path == "" {
		return fmt.Errorf("system config is not supported on %s", platform.OSName())
	}

	// MkdirAll and WriteFile honor the process umask, so a hardened root
	// umask (e.g. 077) would otherwise leave the managed config unreadable
	// by non-root users, which would silently disable the system-wide policy
	// for them. The directories are checked before any write: an account
	// that can write them could plant a file that the merge below would take
	// in and that ProtectSystemPath would then make root owned. An existing
	// config file is merged only when PMG wrote it and only the system
	// account controls it.
	if err := platform.PrepareSystemDir(filepath.Dir(path)); err != nil {
		return err
	}
	if err := requireTrustedManagedFile(path); err != nil {
		return err
	}
	if err := requireSystemControlledBeforeWrite(path); err != nil {
		return err
	}

	if err := writeTemplateConfigFile(path); err != nil {
		return err
	}

	if err := platform.ProtectSystemPath(path, 0o644); err != nil {
		return err
	}

	// PrepareSystemDir leaves an existing Unix directory unchanged. A
	// directory that another account owns or may write makes the runtime
	// ignore the file, so the install fails instead of reporting success.
	return requireSystemControlledConfig(path)
}

// RemoveSystemConfigFile deletes the globally managed config file. A missing
// file is not an error. Returns an error when the platform has no system path.
func requireTrustedManagedFile(path string) error {
	if err := platform.RequireTrustedSystemFile(path); err != nil {
		return usefulerror.NewUsefulError().
			WithCode(errcodes.PermissionDenied).
			WithHumanError(fmt.Sprintf("the managed config %s is not a file PMG wrote", path)).
			WithHelp("Inspect the file, delete it, and run the install again").
			Wrap(err)
	}
	return nil
}

func RemoveSystemConfigFile() error {
	path := globalConfigFilePath()
	if path == "" {
		return fmt.Errorf("system config is not supported on %s", platform.OSName())
	}

	return platform.RemoveSystemFile(path)
}

// SystemConfigDir returns the OS-level managed config directory, or "" when
// unsupported.
func SystemConfigDir() string {
	return globalConfigDir()
}

// SystemConfigFilePath returns the OS-level managed config file, or "" when
// unsupported.
func SystemConfigFilePath() string {
	return globalConfigFilePath()
}

func writeTemplateConfigFile(configFilePath string) error {
	if err := os.MkdirAll(filepath.Dir(configFilePath), 0o755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	existingConfig, err := os.ReadFile(configFilePath)
	if os.IsNotExist(err) {
		return os.WriteFile(configFilePath, []byte(templateConfig), 0o644)
	}
	if err != nil {
		return fmt.Errorf("failed to read existing config: %w", err)
	}

	merged, err := utils.MergeYAML(existingConfig, []byte(templateConfig))
	if err != nil {
		return fmt.Errorf("failed to merge config: %w", err)
	}

	if err := os.WriteFile(configFilePath, merged, 0o644); err != nil {
		return fmt.Errorf("failed to write merged config: %w", err)
	}

	return nil
}

func removeFileIfExists(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove config file %q: %w", path, err)
	}

	return nil
}

// NewManagedConfigError returns the error shown when a user tries to change a
// globally managed configuration. It carries a useful error code and help text
// so the CLI presents it as an expected, actionable failure rather than a bug.
func NewManagedConfigError() error {
	return managedError(fmt.Sprintf("configuration is globally managed (%s) and cannot be changed", globalConfig.configFilePath))
}

// RequireUserScope returns nil when a config write without --system may
// change the per-user file. A managed config refuses, and names --system
// when the process is root, because root may change that file. Sudo without
// a managed config refuses too, because the write would land in root's
// per-user file.
func RequireUserScope(command string) error {
	if globalConfig.IsManaged() {
		if platform.IsPrivileged() {
			return newManagedNeedsSystemError(command)
		}
		return NewManagedConfigError()
	}
	if platform.IsSudo() {
		return NewSudoNeedsSystemError(command)
	}
	return nil
}

func newManagedNeedsSystemError(command string) error {
	human := fmt.Sprintf("configuration is globally managed (%s), and only `pmg config %s --system` changes it",
		globalConfig.configFilePath, command)
	return usefulerror.NewUsefulError().
		WithCode(errcodes.PermissionDenied).
		WithHumanError(human).
		WithHelp(fmt.Sprintf("Run `pmg config %s --system` to change the managed config.", command)).
		Wrap(errors.New(human))
}

// NewSudoNeedsSystemError refuses a config write under sudo that names no
// scope. Without --system the command would change root's per-user file,
// which the user never sees and no daemon is meant to read.
func NewSudoNeedsSystemError(command string) error {
	rootPath, err := RootUserConfigFilePath()
	if err != nil {
		rootPath = globalConfig.userConfigFilePath
	}
	help := "Run the command without sudo for your own config."
	if system := globalConfigFilePath(); system != "" {
		help = fmt.Sprintf("Use `--system` for the managed config at %s, or run the command without sudo for your own.", system)
	}
	// cobra prints the wrapped error, so it carries the sentence a user
	// needs, as managedError does.
	human := fmt.Sprintf("under sudo, `pmg config %s` would change root's per-user config at %s", command, rootPath)
	return usefulerror.NewUsefulError().
		WithCode(errcodes.PermissionDenied).
		WithHumanError(human).
		WithHelp(help).
		Wrap(errors.New(human))
}

// RequireSystemScope returns nil when the process may change the managed
// config, which is root only. The error names the command and says to use
// sudo.
func RequireSystemScope(command string) error {
	if platform.IsPrivileged() {
		return nil
	}
	human := fmt.Sprintf("`%s` requires root", command)
	return usefulerror.NewUsefulError().
		WithCode(errcodes.PermissionDenied).
		WithHumanError(human).
		WithHelp(fmt.Sprintf("Run it as root: `sudo %s`", command)).
		Wrap(errors.New(human))
}

// managedError builds the standard "globally managed" CLI error with a useful
// code and actionable help.
func managedError(message string) error {
	return usefulerror.NewUsefulError().
		WithCode(errcodes.PermissionDenied).
		WithHumanError(message).
		WithHelp("This machine's PMG configuration is centrally managed. Contact your administrator to change it.").
		Wrap(errors.New(message))
}
