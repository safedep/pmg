package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// loadViperConfig loads the configuration using Viper if available.
// It returns an error if the config file exists but cannot be read or parsed,
// allowing the caller to fall back to default configuration.
func loadViperConfig() error {
	configPath, err := configFilePath()
	if err != nil {
		return fmt.Errorf("failed to get config file path: %w", err)
	}

	// Check if config file exists before attempting to load
	// If it doesn't exist, we use the default configuration (see config.go)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil
	}

	v := viper.New()

	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")
	v.SetEnvPrefix("PMG")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	// Unmarshal directly into globalConfig.Config (which already holds DefaultConfig() values)
	// instead of a fresh zero-value struct. Viper uses mapstructure with ZeroFields=false,
	// so keys missing from the YAML retain their defaults. This is critical for users who
	// upgrade PMG without re-running "pmg setup install" — their old config.yml won't have
	// newer keys (e.g. dependency_cooldown), and those must fall back to defaults rather than
	// silently becoming Go zero values (false/0/"").
	if err := v.Unmarshal(&globalConfig.Config); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return nil
}
