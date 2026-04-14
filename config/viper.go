package config

import (
	"fmt"
	"os"
	"reflect"
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

	// Register all config struct fields as Viper defaults so that env vars work
	// for any key Viper wouldn't otherwise know about — either because there is no
	// config file, or because the key is absent from the file (e.g. commented out,
	// or a new key added after the user last ran "pmg setup install").
	registerViperDefaults(v, globalConfig.Config, "")

	// Merge the user config file on top if it exists.
	if _, statErr := os.Stat(configPath); statErr == nil {
		v.SetConfigFile(configPath)
		if err := v.MergeInConfig(); err != nil {
			return fmt.Errorf("failed to read config file %s: %w", configPath, err)
		}
	}

	// Unmarshal into a copy of the current defaults so that keys absent from
	// both the env and the user config file retain their Go defaults.
	merged := globalConfig.Config
	if err := v.Unmarshal(&merged); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	globalConfig.Config = merged
	return nil
}

// registerViperDefaults walks cfg (a struct) recursively via reflection and registers
// each field as a Viper default using its mapstructure tag as the key. This is the
// minimum required for AutomaticEnv to resolve env vars for those keys.
func registerViperDefaults(v *viper.Viper, cfg any, prefix string) {
	t := reflect.TypeOf(cfg)
	val := reflect.ValueOf(cfg)

	if t.Kind() == reflect.Pointer {
		t = t.Elem()
		val = val.Elem()
	}

	if t.Kind() != reflect.Struct {
		return
	}

	for i := range t.NumField() {
		field := t.Field(i)
		fieldVal := val.Field(i)

		tag := field.Tag.Get("mapstructure")
		if tag == "" || tag == "-" {
			continue
		}

		// Strip options like ",squash" or ",omitempty"
		key := strings.SplitN(tag, ",", 2)[0]
		if prefix != "" {
			key = prefix + "." + key
		}

		if field.Type.Kind() == reflect.Struct {
			registerViperDefaults(v, fieldVal.Interface(), key)
		} else {
			v.SetDefault(key, fieldVal.Interface())
		}
	}
}
