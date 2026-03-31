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

	var loadedConfig Config
	if err := v.Unmarshal(&loadedConfig); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	globalConfig.Config = loadedConfig
	return nil
}
