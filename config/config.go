package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	_ "embed"
)

const (
	// Environment variable key for the insecure installation flag
	PMG_INSECURE_INSTALLATION_ENV_KEY = "PMG_INSECURE_INSTALLATION"

	// Allow overriding the config path from the environment
	CONFIG_DIR_ENV_KEY = "PMG_CONFIG_DIR"

	// Config path is computed as the user config directory + the default relative path
	// when not overridden by the environment variable
	CONFIG_DEFAULT_HOME_RELATIVE_PATH = "safedep/pmg"

	// Default log directory is relative to the config directory.
	CONFIG_DEFAULT_LOG_DIR = "logs"

	// Config file name.
	// Important: The config file path and the schema should be backward compatible. In case of breaking config
	// changes, we must introduce a new file name and a migration path.
	CONFIG_FILE_NAME = "config.yml"
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

	// Paranoid mode enables active scanning of unknown packages for malware.
	Paranoid bool `mapstructure:"paranoid"`

	// TrustedPackages allows for trusting a suspicious package and ignoring the suspicious behaviour for the package in future installations
	TrustedPackages []TrustedPackage `mapstructure:"trusted_packages"`

	// SkipEventLogging allows for skipping event logging.
	SkipEventLogging bool `mapstructure:"skip_event_logging"`

	// EventLogRetentionDays is the number of days to retain event logs.
	EventLogRetentionDays int `mapstructure:"event_log_retention_days"`
}

// TrustedPackage is a package that is trusted by the user and will be ignored by the security guardrails.
type TrustedPackage struct {
	Purl   string `mapstructure:"purl"`
	Reason string `mapstructure:"reason"`
}

// RuntimeConfig is the configuration that is used at runtime. It contains static configuration
// that can be loaded from a source and, if allowed, overridden by the user at runtime.
type RuntimeConfig struct {
	Config Config

	// DryRun enables dry-run mode for the package manager, where actual execution of commands is skipped.
	DryRun bool

	// InsecureInstallation allows bypassing install blocking on malicious packages
	InsecureInstallation bool

	// Internal config values computed at runtime and must be accessed via. API
	configDir      string
	configFilePath string
	eventLogDir    string
}

// ConfigFilePath returns the path to the config file.
func (r *RuntimeConfig) ConfigFilePath() string {
	return r.configFilePath
}

// EventLogDir returns the path to the event log directory.
func (r *RuntimeConfig) EventLogDir() string {
	return r.eventLogDir
}

// DefaultConfig is a fail safe contract for the runtime configuration.
// The config package return an appropriate RuntimeConfig based on the environment and the configuration.
func DefaultConfig() RuntimeConfig {
	// Backward compatibility for the insecure installation flag before config was introduced.
	insecureInstallation := false
	if val := os.Getenv(PMG_INSECURE_INSTALLATION_ENV_KEY); val != "" {
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
			EventLogRetentionDays:  7,
			SkipEventLogging:       false,
			TrustedPackages:        []TrustedPackage{},
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
}

// loadConfig loads the configuration from the config file.
// This is where we determine the source of config and use the appropriate loader.
// Right now we only support loading from a config file using Viper. All loader
// functions should be safe with reasonable defaults and panic only in case of system errors.
func loadConfig() {
	loadViperConfig()
}

// configDir computes the path to the config directory.
func configDir() (string, error) {
	dir := os.Getenv(CONFIG_DIR_ENV_KEY)
	if dir != "" {
		return dir, nil
	}

	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve user config directory: %w", err)
	}

	return filepath.Join(userConfigDir, CONFIG_DEFAULT_HOME_RELATIVE_PATH), nil
}

// configFilePath computes the path to the config file.
func configFilePath() (string, error) {
	configDir, err := configDir()
	if err != nil {
		return "", fmt.Errorf("failed to get config directory: %w", err)
	}

	return filepath.Join(configDir, CONFIG_FILE_NAME), nil
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
				return "", fmt.Errorf("could not determine Windows user directory")
			}

			return filepath.Join(baseDir, CONFIG_DEFAULT_HOME_RELATIVE_PATH, CONFIG_DEFAULT_LOG_DIR), nil
		}

		return filepath.Join(baseDir, "pmg", "logs"), nil
	case "darwin", "linux":
		configDir, err := configDir()
		if err != nil {
			return "", fmt.Errorf("failed to get config directory: %w", err)
		}

		return filepath.Join(configDir, CONFIG_DEFAULT_LOG_DIR), nil
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

// WriteTemplateConfig writes the template configuration file to disk if it doesn't already exist.
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

	// Do not overwrite the config file if it already exists
	if _, err := os.Stat(configFilePath); err == nil {
		return nil
	}

	if err := os.WriteFile(configFilePath, []byte(templateConfig), 0o644); err != nil {
		return fmt.Errorf("failed to write template config: %w", err)
	}

	return nil
}
