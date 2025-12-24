package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigIsNeverNil(t *testing.T) {
	config := Get()
	assert.NotNil(t, config)
}

func TestConfigHasDefaultValues(t *testing.T) {
	t.Run("with non-existent config directory", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "/tmp/pmg-test/random-does-not-exist")
		initConfig()

		config := Get()
		assert.Equal(t, true, config.Config.Transitive)
		assert.Equal(t, 5, config.Config.TransitiveDepth)
		assert.Equal(t, false, config.Config.IncludeDevDependencies)
		assert.Equal(t, false, config.Config.Paranoid)
		assert.Equal(t, []TrustedPackage{}, config.Config.TrustedPackages)
		assert.Equal(t, "/tmp/pmg-test/random-does-not-exist", config.configDir)
		assert.Equal(t, "/tmp/pmg-test/random-does-not-exist/config.yml", config.configFilePath)
	})

	t.Run("when no config directory is set", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "")
		initConfig()

		config := Get()

		userConfigDir, err := os.UserConfigDir()
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, filepath.Join(userConfigDir, ".safedep/pmg"), config.configDir)
		assert.Equal(t, filepath.Join(userConfigDir, ".safedep/pmg/config.yml"), config.configFilePath)
	})
}
