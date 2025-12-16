package config

import (
	"context"
	"fmt"
	"strings"

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

	// TrustedPackages allows for trusting an suspicious package and ignoring the suspicious behaviour for the package in future installations
	TrustedPackages []string `mapstructure:"trusted_packages"`
}

func SetupViper() (string, error) {
	dir, err := PmgConfigDir()
	if err != nil {
		return "", err
	}

	viper.SetConfigName(pmgConfigName)
	viper.SetConfigType(pmgConfigType)
	viper.AddConfigPath(dir)

	viper.SetEnvPrefix("PMG")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	// Defaults
	viper.SetDefault("transitive", true)
	viper.SetDefault("transitive_depth", 5)
	viper.SetDefault("include_dev_dependencies", false)
	viper.SetDefault("dry_run", false)
	viper.SetDefault("paranoid", false)
	viper.SetDefault("insecure_installation", false)
	viper.SetDefault("trusted_packages", []string{})

	cfgPath, err := ConfigFilePath()
	if err != nil {
		return "", err
	}
	return cfgPath, nil
}

func BindFlags(fs *pflag.FlagSet) {
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

func Load(fs *pflag.FlagSet) (Config, error) {
	if _, err := SetupViper(); err != nil {
		return Config{}, err
	}

	// Bind CLI flags so they override config/env
	BindFlags(fs)

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
