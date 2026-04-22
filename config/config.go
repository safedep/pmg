package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	_ "embed"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/dry/utils"
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

	// Config path is computed as the user config directory + the default relative path
	// when not overridden by the environment variable
	pmgDefaultHomeRelativePath = "safedep/pmg"

	// Default log directory is relative to the config directory.
	pmgDefaultLogDir = "logs"

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

	// ProxyMode enables proxy-based package interception when supported by package managers.
	// When enabled, PMG starts a proxy server and intercepts package manager requests in real-time.
	ProxyMode bool `mapstructure:"proxy_mode"`

	// ExperimentalProxyMode is same as ProxyMode. Kept here for backward compatibility because
	// we initially introduced it as an experimental feature.
	ExperimentalProxyMode bool `mapstructure:"experimental_proxy_mode"`

	// ProxyInstallOnly restricts proxy interception to install commands only.
	// When false (default), proxy runs for all package manager commands.
	// When true, non-install commands (e.g., npm ls, pip list) bypass the proxy and execute directly.
	ProxyInstallOnly bool `mapstructure:"proxy_install_only"`

	// Verbosity controls the UI verbosity level. Valid values: "silent", "normal", "verbose".
	Verbosity string `mapstructure:"verbosity"`

	// Sandbox enables sandboxing of package manager processes with controlled filesystem,
	// network, and process execution access. Provides defense-in-depth against supply chain attacks.
	Sandbox SandboxConfig `mapstructure:"sandbox"`

	DependencyCooldown DependencyCooldownConfig `mapstructure:"dependency_cooldown"`

	Cloud CloudConfig `mapstructure:"cloud"`
}

// CloudConfig configures audit event sync to SafeDep Cloud.
type CloudConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	EndpointID string `mapstructure:"endpoint_id"`
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
	configDir      string
	configFilePath string
	eventLogDir    string
}

// CloudSyncDBPath returns the path to the cloud sync WAL database.
func (r *RuntimeConfig) CloudSyncDBPath() string {
	return filepath.Join(r.configDir, "cloud-sync.db")
}

// ConfigFilePath returns the path to the config file.
func (r *RuntimeConfig) ConfigFilePath() string {
	return r.configFilePath
}

// EventLogDir returns the path to the event log directory.
func (r *RuntimeConfig) EventLogDir() string {
	return r.eventLogDir
}

// ConfigDir returns the path to the config directory.
func (r *RuntimeConfig) ConfigDir() string {
	return r.configDir
}

// IsProxyModeEnabled is a helper function to check for proxy mode with
// support for backward compatibility
func (r *RuntimeConfig) IsProxyModeEnabled() bool {
	return (r.Config.ExperimentalProxyMode || r.Config.ProxyMode)
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
	insecureInstallation := false
	if val := os.Getenv(pmgInsecureInstallationEnvKey); val != "" {
		if boolVal, err := strconv.ParseBool(val); err == nil {
			insecureInstallation = boolVal
		}
	}

	return RuntimeConfig{
		Config: Config{
			Transitive:             true,
			TransitiveDepth:        5,
			IncludeDevDependencies: false,
			Paranoid:               false,
			DisableTelemetry:       false,
			EventLogRetentionDays:  7,
			SkipEventLogging:       false,
			ExperimentalProxyMode:  false,
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

// initConfig should be idempotent and can be called multiple times.
// This is required for testing purposes.
func initConfig() {
	defaultConfig := DefaultConfig()
	globalConfig = &defaultConfig

	configDir, err := configDir()
	if err != nil {
		panic(fmt.Errorf("failed to get config directory: %w", err))
	}

	configFilePath, err := configFilePath()
	if err != nil {
		panic(fmt.Errorf("failed to get config file path: %w", err))
	}

	eventLogDir, err := eventLogDir()
	if err != nil {
		panic(fmt.Errorf("failed to get event log directory: %w", err))
	}

	globalConfig.configDir = configDir
	globalConfig.configFilePath = configFilePath
	globalConfig.eventLogDir = eventLogDir

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

// configFilePath computes the path to the config file.
func configFilePath() (string, error) {
	configDir, err := configDir()
	if err != nil {
		return "", fmt.Errorf("failed to get config directory: %w", err)
	}

	return filepath.Join(configDir, pmgConfigFileName), nil
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

// Get returns the global configuration.
// This is the public API for the configuration package. This package should guarantee
// that this function will never return nil.
func Get() *RuntimeConfig {
	return globalConfig
}

func ConfigureSandbox(isInstallationCommand bool) {
	if globalConfig.Config.Sandbox.Enabled {
		// Apply sandbox to all commands if EnforceAlways=true, otherwise only to
		// installation commands else disable the sandbox
		globalConfig.Config.Sandbox.Enabled = globalConfig.Config.Sandbox.EnforceAlways || isInstallationCommand
	}
}

// WriteTemplateConfig writes the template configuration file to disk.
// If the config file does not exist, the full template is written.
// If it already exists, missing keys from the template are merged
// into the existing config while preserving all user values and comments.
func WriteTemplateConfig() error {
	configDir, err := configDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configFilePath, err := configFilePath()
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
