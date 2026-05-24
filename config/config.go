package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	_ "embed"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
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

	// Default sandbox violation cache directory is relative to the cache root.
	pmgDefaultSandboxViolationCacheDir = "sandbox/violations"

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
	Transitive             bool `mapstructure:"transitive"`
	TransitiveDepth        int  `mapstructure:"transitive_depth"`
	IncludeDevDependencies bool `mapstructure:"include_dev_dependencies"`

	// Paranoid enables high-security defaults (e.g., treating suspicious behavior as malicious).
	Paranoid bool `mapstructure:"paranoid"`

	// DisableTelemetry allows turning off telemetry collection.
	DisableTelemetry bool `mapstructure:"disable_telemetry"`

	// TrustedPackages allows for trusting a suspicious package and ignoring the suspicious behaviour for the package in future installations
	TrustedPackages []TrustedPackage `mapstructure:"trusted_packages"`

	// SkipEventLogging allows for skipping event logging.
	SkipEventLogging bool `mapstructure:"skip_event_logging"`

	// EventLogRetentionDays is the number of days to retain event logs.
	EventLogRetentionDays int `mapstructure:"event_log_retention_days"`

	// Deprecated: Use Proxy.Enabled instead. Kept for backward compatibility with old config files.
	ProxyMode bool `mapstructure:"proxy_mode"`

	// Deprecated: Use Proxy.InstallOnly instead. Kept for backward compatibility with old config files.
	ProxyInstallOnly bool `mapstructure:"proxy_install_only"`

	// Verbosity controls the UI verbosity level. Valid values: "silent", "normal", "verbose".
	Verbosity string `mapstructure:"verbosity"`

	// Sandbox enables sandboxing of package manager processes with controlled filesystem,
	// network, and process execution access. Provides defense-in-depth against supply chain attacks.
	Sandbox SandboxConfig `mapstructure:"sandbox"`

	DependencyCooldown DependencyCooldownConfig `mapstructure:"dependency_cooldown"`

	Cloud CloudConfig `mapstructure:"cloud"`

	Proxy ProxyConfig `mapstructure:"proxy"`
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
	Enabled      bool                `mapstructure:"enabled"`
	InstallOnly  bool                `mapstructure:"install_only"`
	SkipCommands map[string][]string `mapstructure:"skip_commands"`
}

// SandboxConfig configures the sandbox system for isolating package manager processes.
type SandboxConfig struct {
	// Enabled enables sandbox mode (opt-in by default for backward compatibility).
	Enabled bool `mapstructure:"enabled"`

	// EnforceAlways controls scope of sandbox enforcement:
	// - When true: sandbox applies to all package manager commands
	// - When false: sandbox only applies to install commands, others run unrestricted (default)
	EnforceAlways bool `mapstructure:"enforce_always"`

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

	// Pre-parsed PURL components (not serialized, computed at load time)
	// These fields avoid repeated PURL parsing on every IsTrustedPackage() call
	parsed    bool
	ecosystem packagev1.Ecosystem
	name      string
	version   string
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

	// Internal config values computed at runtime and must be accessed via. API
	configDir                string
	configFilePath           string // active config: globally managed file if present, else per-user
	userConfigFilePath       string // per-user config file, used for writes and removal
	configLocked             bool   // global file present and opted into lockdown (global_lockdown: true)
	eventLogDir              string
	sandboxProfileDir        string
	sandboxViolationCacheDir string
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

// ConfigFilePath returns the path to the active config file (the globally
// managed file when present, otherwise the per-user file).
func (r *RuntimeConfig) ConfigFilePath() string {
	return r.configFilePath
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

// SandboxViolationCacheDir returns the path to the sandbox violation cache directory.
func (r *RuntimeConfig) SandboxViolationCacheDir() string {
	return r.sandboxViolationCacheDir
}

func (r *RuntimeConfig) IsProxyModeEnabled() bool {
	return r.Config.Proxy.Enabled
}

// SandboxAllowType represents the type of a sandbox allow override.
type SandboxAllowType string

const (
	SandboxAllowRead       SandboxAllowType = "read"
	SandboxAllowWrite      SandboxAllowType = "write"
	SandboxAllowExec       SandboxAllowType = "exec"
	SandboxAllowNetConnect SandboxAllowType = "net-connect"
	SandboxAllowNetBind    SandboxAllowType = "net-bind"
)

// SandboxAllowOverride represents a single --sandbox-allow flag value.
type SandboxAllowOverride struct {
	// Type is the resource type (read, write, exec, net-connect, net-bind).
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
			Transitive:             true,
			TransitiveDepth:        5,
			IncludeDevDependencies: false,
			Paranoid:               false,
			DisableTelemetry:       false,
			EventLogRetentionDays:  7,
			SkipEventLogging:       false,
			TrustedPackages:        []TrustedPackage{},
			ProxyMode:              true,
			Verbosity:              VerbosityNormal,
			Sandbox: SandboxConfig{
				Enabled:       false,
				EnforceAlways: false,
			},
			DependencyCooldown: DependencyCooldownConfig{
				Enabled: true,
				Days:    5,
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
				Enabled:      true,
				InstallOnly:  false,
				SkipCommands: map[string][]string{},
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

	configDir, err := configDir()
	if err != nil {
		panic(fmt.Errorf("failed to get config directory: %w", err))
	}

	activeConfigPath, err := resolveConfigFile()
	if err != nil {
		panic(fmt.Errorf("failed to resolve config file path: %w", err))
	}

	userConfigPath, err := userConfigFilePath()
	if err != nil {
		panic(fmt.Errorf("failed to get user config file path: %w", err))
	}

	eventLogDir, err := eventLogDir()
	if err != nil {
		panic(fmt.Errorf("failed to get event log directory: %w", err))
	}

	sandboxProfileDir, err := sandboxProfileDir()
	if err != nil {
		panic(fmt.Errorf("failed to get sandbox profile directory: %w", err))
	}

	sandboxViolationCacheDir, err := sandboxViolationCacheDir()
	if err != nil {
		panic(fmt.Errorf("failed to get sandbox violation cache directory: %w", err))
	}

	globalConfig.configDir = configDir
	globalConfig.configFilePath = activeConfigPath
	globalConfig.userConfigFilePath = userConfigPath
	globalConfig.eventLogDir = eventLogDir
	globalConfig.sandboxProfileDir = sandboxProfileDir
	globalConfig.sandboxViolationCacheDir = sandboxViolationCacheDir

	// A globally managed config enforces lockdown only when it opts in via
	// global_lockdown, read straight from the file so it cannot be flipped by
	// env or CLI.
	globalConfig.configLocked = globalConfig.IsManaged() && globalConfigEnablesLockdown(globalConfigFilePath())

	// When locked, env cannot bypass the config, including the
	// PMG_INSECURE_INSTALLATION malicious-package block bypass.
	if globalConfig.IsLocked() {
		globalConfig.InsecureInstallation = false
	}

	loadConfig()

	if err := preprocessTrustedPackages(&globalConfig.Config); err != nil {
		log.Warnf("Failed to preprocess trusted packages: %v", err)
	}
}

// loadConfig loads the configuration from the config file.
// This is where we determine the source of config and use the appropriate loader.
// Right now we only support loading from a config file using Viper. If loading
// fails, the default configuration is used and a warning is logged.
func loadConfig() {
	if err := loadViperConfig(); err != nil {
		log.Warnf("Failed to load config, using defaults: %v", err)
	}
}

// configDir computes the path to the config directory.
func configDir() (string, error) {
	dir := os.Getenv(pmgConfigDirEnvKey)
	if dir != "" {
		return dir, nil
	}

	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve user config directory: %w", err)
	}

	return filepath.Join(userConfigDir, pmgDefaultHomeRelativePath), nil
}

// userConfigFilePath computes the path to the per-user config file.
func userConfigFilePath() (string, error) {
	configDir, err := configDir()
	if err != nil {
		return "", fmt.Errorf("failed to get config directory: %w", err)
	}

	return filepath.Join(configDir, pmgConfigFileName), nil
}

// globalConfigDirOverride replaces the OS-level managed config directory. It
// exists only for tests within this package. There is intentionally no env var
// or flag for it, so a user cannot point the "managed" config at their own file
// and bypass the globally managed config.
var globalConfigDirOverride string

// globalConfigDir returns the OS-level directory for a globally managed config
// file, or "" when the platform has no such location.
func globalConfigDir() string {
	if globalConfigDirOverride != "" {
		return globalConfigDirOverride
	}

	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/safedep/pmg"
	case "linux":
		return "/etc/safedep/pmg"
	case "windows":
		programData := os.Getenv("PROGRAMDATA")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "safedep", "pmg")
	}

	return ""
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

// resolveConfigFile picks the active config file. The globally managed file,
// when present, is authoritative and the per-user file is ignored entirely.
func resolveConfigFile() (string, error) {
	if global := globalConfigFilePath(); global != "" && isRegularFile(global) {
		return global, nil
	}

	return userConfigFilePath()
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// eventLogDir computes the path to the event log directory.
func eventLogDir() (string, error) {
	// For rationale on why different directory for Windows, see:
	// https://github.com/safedep/pmg/pull/82#discussion_r2636746036
	switch runtime.GOOS {
	case "windows":
		// Windows: %LOCALAPPDATA%\safedep\pmg\logs or %USERPROFILE%\safedep\pmg\logs
		baseDir := os.Getenv("LOCALAPPDATA")
		if baseDir == "" {
			baseDir = os.Getenv("USERPROFILE")
			if baseDir == "" {
				return "", fmt.Errorf("could not determine Windows user directory for event log storage")
			}
		}

		return filepath.Join(baseDir, pmgDefaultHomeRelativePath, pmgDefaultLogDir), nil
	case "darwin", "linux":
		configDir, err := configDir()
		if err != nil {
			return "", fmt.Errorf("failed to get config directory: %w", err)
		}

		return filepath.Join(configDir, pmgDefaultLogDir), nil
	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// cacheDir computes the path to the cache root directory.
func cacheDir() (string, error) {
	dir := os.Getenv(pmgCacheDirEnvKey)
	if dir != "" {
		return dir, nil
	}

	switch runtime.GOOS {
	case "windows":
		// Windows: %LOCALAPPDATA%\safedep\pmg or %USERPROFILE%\safedep\pmg
		baseDir := os.Getenv("LOCALAPPDATA")
		if baseDir == "" {
			baseDir = os.Getenv("USERPROFILE")
			if baseDir == "" {
				return "", fmt.Errorf("could not determine Windows user directory for cache storage")
			}
		}
		return filepath.Join(baseDir, pmgDefaultHomeRelativePath), nil
	case "darwin", "linux":
		userCacheDir, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("failed to retrieve user cache directory: %w", err)
		}
		return filepath.Join(userCacheDir, pmgDefaultHomeRelativePath), nil
	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// sandboxProfileDir computes the path to the sandbox profile directory.
func sandboxProfileDir() (string, error) {
	configDir, err := configDir()
	if err != nil {
		return "", fmt.Errorf("failed to get config directory: %w", err)
	}

	return filepath.Join(configDir, pmgDefaultSandboxProfileDir), nil
}

// sandboxViolationCacheDir computes the path to the sandbox violation cache directory.
func sandboxViolationCacheDir() (string, error) {
	cacheDir, err := cacheDir()
	if err != nil {
		return "", fmt.Errorf("failed to get cache directory: %w", err)
	}

	return filepath.Join(cacheDir, pmgDefaultSandboxViolationCacheDir), nil
}

// Get returns the global configuration.
// This is the public API for the configuration package. This package should guarantee
// that this function will never return nil.
func Get() *RuntimeConfig {
	return globalConfig
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

	configDir, err := configDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configFilePath, err := userConfigFilePath()
	if err != nil {
		return fmt.Errorf("failed to get config file path: %w", err)
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

// RemoveUserConfigFile deletes the per-user config file. It never touches the
// globally managed file. A missing file is not an error.
func RemoveUserConfigFile() error {
	path, err := userConfigFilePath()
	if err != nil {
		return fmt.Errorf("failed to get config file path: %w", err)
	}

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

// managedError builds the standard "globally managed" CLI error with a useful
// code and actionable help.
func managedError(message string) error {
	return usefulerror.NewUsefulError().
		WithCode(errcodes.PermissionDenied).
		WithHumanError(message).
		WithHelp("This machine's PMG configuration is centrally managed. Contact your administrator to change it.").
		Wrap(errors.New(message))
}
