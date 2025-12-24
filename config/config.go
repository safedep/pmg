package config

import (
	"fmt"
	"os"
	"path/filepath"
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
	CONFIG_DEFAULT_HOME_RELATIVE_PATH = ".safedep/pmg"

	// Config file name
	CONFIG_FILE_NAME = "config.yml"

	// Alias file name for storing shell aliases
	CONFIG_ALIAS_FILE_NAME = "aliases.rc"
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
			TrustedPackages:        []TrustedPackage{},
		},
		DryRun:               false,
		InsecureInstallation: insecureInstallation,
	}
}

// ConfigRepository is a contract for a repository that can load and save the configuration.
type ConfigRepository interface {
	// Load loads the configuration from the repository.
	// The path is the path to the config file or a namespace for remote repositories when supported.
	Load(path string) (Config, error)

	// Save saves the configuration to the repository.
	Save(path string) error
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

	globalConfig.configDir = configDir
	globalConfig.configFilePath = configFilePath

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

// Get returns the global configuration.
// This is the public API for the configuration package. This package should guarantee
// that this function will never return nil.
func Get() *RuntimeConfig {
	return globalConfig
}

// ConfigFilePath returns the path to the config file.
func (r *RuntimeConfig) ConfigFilePath() string {
	return r.configFilePath
}

// Save saves the configuration to the config file.
func WriteTemplateConfig() error {
	configFilePath, err := configFilePath()
	if err != nil {
		return fmt.Errorf("failed to get config file path: %w", err)
	}

	if err := os.WriteFile(configFilePath, []byte(templateConfig), 0o644); err != nil {
		return fmt.Errorf("failed to write template config: %w", err)
	}

	return nil
}
