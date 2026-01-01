package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// loadViperConfig loads the configuration using Viper if available.
// This function will panic for system errors since it is part of the init path.
func loadViperConfig() {
	configPath, err := configFilePath()
	if err != nil {
		panic(fmt.Errorf("failed to get config file path: %w", err))
	}

	// Check if config file exists before attempting to load
	// If it doesn't exist, we use the default configuration (see config.go)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return
	}

	v := viper.New()

	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")
	v.SetEnvPrefix("PMG")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	if err := v.ReadInConfig(); err != nil {
		panic(fmt.Errorf("failed to read config file %s: %w", configPath, err))
	}

	var loadedConfig Config
	if err := v.Unmarshal(&loadedConfig); err != nil {
		panic(fmt.Errorf("failed to unmarshal config: %w", err))
	}

	globalConfig.Config = loadedConfig
}
