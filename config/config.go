package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type configKey struct{}
type contextValue struct {
	Config Config
}

// Global configuration
type Config struct {
	Transitive             bool `mapstructure:"transitive"`
	TransitiveDepth        int  `mapstructure:"transitive_depth"`
	IncludeDevDependencies bool `mapstructure:"include_dev_dependencies"`
	Paranoid               bool `mapstructure:"paranoid"`

	// DryRun to check for packages for risks.
	// Do not actually execute any commands.
	DryRun bool `mapstructure:"dry_run"`

	// InsecureInstallation allows bypassing install blocking on malicious packages
	InsecureInstallation bool `mapstructure:"insecure_installation"`

	// TrustedPackages allows for trusting a suspicious package and ignoring the suspicious behaviour for the package in future installations
	TrustedPackages TrustedPackage `mapstructure:"trusted_packages"`
}

type TrustedPackage struct {
	// Purl of the trusted package. Eg. pkg:npm/express@5.2.1
	Purl []string `mapstructure:"purls"`
}

var (
	setupOnce sync.Once
	setupErr  error
)

// ErrConfigAlreadyExists is returned when creating the config without force and it already exists.
var ErrConfigAlreadyExists = errors.New("pmg config already exists")

// DefaultConfig returns the canonical default configuration used by PMG.
func DefaultConfig() Config {
	return Config{
		Transitive:             true,
		TransitiveDepth:        5,
		IncludeDevDependencies: false,
		Paranoid:               false,
		DryRun:                 false,
		InsecureInstallation:   false,
		TrustedPackages:        TrustedPackage{Purl: []string{}},
	}
}

func Load(fs *pflag.FlagSet) (Config, error) {
	if err := ensureViperConfigured(); err != nil {
		return Config{}, err
	}

	// Bind CLI flags so they override config/env
	bindFlags(fs)

	// Read the config file if it exists
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return Config{}, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return cfg, nil
}

// CreateConfig writes the PMG config file and returns its absolute path.
func CreateConfig() (string, error) {
	if _, err := createConfigDir(); err != nil {
		return "", err
	}

	cfgFile, err := ConfigFilePath()
	if err != nil {
		return "", err
	}

	writer := viper.New()
	writer.SetConfigType(pmgConfigType)

	defaults := DefaultConfig()
	if err := writer.MergeConfigMap(configAsMap(defaults)); err != nil {
		return "", fmt.Errorf("failed to prepare default config: %w", err)
	}

	writeErr := writer.WriteConfigAs(cfgFile)

	if writeErr != nil {
		var alreadyExistsErr viper.ConfigFileAlreadyExistsError
		if errors.As(writeErr, &alreadyExistsErr) {
			return cfgFile, ErrConfigAlreadyExists
		}
		return "", fmt.Errorf("error writing config file: %w", writeErr)
	}

	if err := ensureViperConfigured(); err == nil {
		for key, value := range configAsMap(defaults) {
			viper.Set(key, value)
		}
	}

	return cfgFile, nil
}

// RemoveConfig removes the PMG configuration directory and its contents.
func RemoveConfig() error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}

	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("failed to remove config directory %s: %w", dir, err)
	}
	return nil
}

// Inject config into context while protecting against context poisoning
func (c Config) Inject(ctx context.Context) context.Context {
	return context.WithValue(ctx, configKey{}, &contextValue{Config: c})
}

// Extract config from context
func FromContext(ctx context.Context) (Config, error) {
	c, ok := ctx.Value(configKey{}).(*contextValue)
	if !ok {
		return Config{}, fmt.Errorf("config not found in context")
	}

	return c.Config, nil
}

func ensureViperConfigured() error {
	setupOnce.Do(func() {
		dir, err := ConfigDir()
		if err != nil {
			setupErr = err
			return
		}

		v := viper.GetViper()
		v.SetConfigName(pmgConfigName)
		v.SetConfigType(pmgConfigType)
		v.AddConfigPath(dir)

		v.SetEnvPrefix("PMG")
		v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
		v.AutomaticEnv()

		for key, value := range configAsMap(DefaultConfig()) {
			v.SetDefault(key, value)
		}
	})

	return setupErr
}

func bindFlags(fs *pflag.FlagSet) {
	if fs == nil {
		return
	}

	// Helper binds a flag if it exists
	bind := func(key, flag string) {
		if f := fs.Lookup(flag); f != nil {
			_ = viper.BindPFlag(key, f)
		}
	}

	bind("transitive", "transitive")
	bind("transitive_depth", "transitive-depth")
	bind("include_dev_dependencies", "include-dev-dependencies")
	bind("dry_run", "dry-run")
	bind("paranoid", "paranoid")
}

// Helper function to map the provided config for setting key/values in viper
func configAsMap(cfg Config) map[string]any {
	return map[string]any{
		"transitive":               cfg.Transitive,
		"transitive_depth":         cfg.TransitiveDepth,
		"include_dev_dependencies": cfg.IncludeDevDependencies,
		"dry_run":                  cfg.DryRun,
		"paranoid":                 cfg.Paranoid,
		"insecure_installation":    cfg.InsecureInstallation,
		"trusted_packages":         cfg.TrustedPackages,
	}
}
