package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// loadViperConfig loads the configuration using Viper.
// Precedence (highest to lowest): cobra flags > env vars > config file > defaults.
// Cobra flags write directly to the config struct after this function runs.
func loadViperConfig() error {
	configPath, err := configFilePath()
	if err != nil {
		return fmt.Errorf("failed to get config file path: %w", err)
	}

	v := viper.New()
	v.SetConfigType("yaml")
	v.SetEnvPrefix("PMG")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	// Load the embedded template as the base so Viper knows all keys and their
	// defaults. This is required for AutomaticEnv to resolve PMG_* env vars for
	// keys that are absent from or newer than the user's config file.
	if err := v.ReadConfig(strings.NewReader(templateConfig)); err != nil {
		return fmt.Errorf("failed to load default config: %w", err)
	}

	// Merge user config on top if it exists.
	if _, statErr := os.Stat(configPath); statErr == nil {
		v.SetConfigFile(configPath)
		if err := v.MergeInConfig(); err != nil {
			return fmt.Errorf("failed to read config file %s: %w", configPath, err)
		}
	}

	merged := globalConfig.Config
	if err := v.Unmarshal(&merged); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	globalConfig.Config = merged
	return nil
}
