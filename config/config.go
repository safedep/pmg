package config

import (
	"context"
	"fmt"

	"github.com/safedep/pmg/internal/ui"
	"github.com/spf13/viper"
)

type configKey struct{}
type contextValue struct {
	Config Config
}

// Global configuration
type Config struct {
	Transitive             bool
	TransitiveDepth        int
	IncludeDevDependencies bool
	Paranoid               bool

	// DryRun to check for packages for risks.
	// Do not actually execute any commands.
	DryRun bool

	// InsecureInstallation allows bypassing install blocking on malicious packages
	InsecureInstallation bool

	// TrustedPackages allows for trusting an suspicious package and ignoring the suspicious behaviour for the package in future installations
	TrustedPackages []string
}

func CreateConfig() error {
	dir, err := PmgConfigDir()
	if err != nil {
		return err
	}

	viper.SetConfigName(pmgConfigName)
	viper.SetConfigType(pmgConfigType)
	viper.AddConfigPath(dir)

	cfgFile, err := ConfigFilePath()
	if err != nil {
		return err
	}

	viper.Set("transitive", true)
	viper.Set("transitive_depth", 5)
	viper.Set("include_dev_dependencies", false)
	viper.Set("dry_run", false)
	viper.Set("paranoid", false)
	viper.Set("trusted_packages", []string{})

	if err := viper.SafeWriteConfigAs(cfgFile); err != nil {
		if _, ok := err.(viper.ConfigFileAlreadyExistsError); ok {
			fmt.Println("Config file already exists, skipping safe write.")
		} else {
			ui.Fatalf("Error writing config file: %v", err)
		}
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
