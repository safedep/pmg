package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSandboxProfileDir(t *testing.T) {
	tests := []struct {
		name     string
		envKey   string
		envVal   string
		expected func(t *testing.T) string
	}{
		{
			name:   "default under user config dir",
			envKey: "PMG_CONFIG_DIR",
			envVal: "",
			expected: func(t *testing.T) string {
				userConfigDir, err := os.UserConfigDir()
				require.NoError(t, err)
				return filepath.Join(userConfigDir, pmgDefaultHomeRelativePath, pmgDefaultSandboxProfileDir)
			},
		},
		{
			name:   "honors PMG_CONFIG_DIR override",
			envKey: "PMG_CONFIG_DIR",
			envVal: "/tmp/pmg-test/custom-config",
			expected: func(t *testing.T) string {
				return filepath.Join("/tmp/pmg-test/custom-config", pmgDefaultSandboxProfileDir)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.envKey, tc.envVal)
			initConfig()

			assert.Equal(t, tc.expected(t), Get().SandboxProfileDir())
		})
	}
}

func TestSandboxProfileDirRespectsXDGConfigHome(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("XDG_CONFIG_HOME is only honored on Linux by os.UserConfigDir")
	}

	tmp := t.TempDir()
	t.Setenv("PMG_CONFIG_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", tmp)
	initConfig()

	expected := filepath.Join(tmp, pmgDefaultHomeRelativePath, pmgDefaultSandboxProfileDir)
	assert.Equal(t, expected, Get().SandboxProfileDir())
}

func TestSandboxOverlayDir(t *testing.T) {
	tests := []struct {
		name     string
		envKey   string
		envVal   string
		expected func(t *testing.T) string
	}{
		{
			name:   "default under user config dir",
			envKey: "PMG_CONFIG_DIR",
			envVal: "",
			expected: func(t *testing.T) string {
				userConfigDir, err := os.UserConfigDir()
				require.NoError(t, err)
				return filepath.Join(userConfigDir, pmgDefaultHomeRelativePath, pmgDefaultSandboxOverlayDir)
			},
		},
		{
			name:   "honors PMG_CONFIG_DIR override",
			envKey: "PMG_CONFIG_DIR",
			envVal: "/tmp/pmg-test/custom-config",
			expected: func(t *testing.T) string {
				return filepath.Join("/tmp/pmg-test/custom-config", pmgDefaultSandboxOverlayDir)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.envKey, tc.envVal)
			initConfig()

			assert.Equal(t, tc.expected(t), Get().SandboxOverlayDir())
		})
	}
}

func TestSandboxViolationCacheDir(t *testing.T) {
	tests := []struct {
		name     string
		envKey   string
		envVal   string
		expected func(t *testing.T) string
	}{
		{
			name:   "default under user cache dir",
			envKey: "PMG_CACHE_DIR",
			envVal: "",
			expected: func(t *testing.T) string {
				base, err := userCacheBase()
				require.NoError(t, err)
				return filepath.Join(base, pmgDefaultHomeRelativePath, pmgDefaultSandboxViolationCacheDir)
			},
		},
		{
			name:   "honors PMG_CACHE_DIR override",
			envKey: "PMG_CACHE_DIR",
			envVal: "/tmp/pmg-test/custom-cache",
			expected: func(t *testing.T) string {
				return filepath.Join("/tmp/pmg-test/custom-cache", pmgDefaultSandboxViolationCacheDir)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PMG_CONFIG_DIR", "")
			t.Setenv(tc.envKey, tc.envVal)
			initConfig()

			assert.Equal(t, tc.expected(t), Get().SandboxViolationCacheDir())
		})
	}
}

func TestSandboxViolationCacheDirRespectsXDGCacheHome(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("XDG_CACHE_HOME is only honored on Linux by os.UserCacheDir")
	}

	tmp := t.TempDir()
	t.Setenv("PMG_CACHE_DIR", "")
	t.Setenv("XDG_CACHE_HOME", tmp)
	initConfig()

	expected := filepath.Join(tmp, pmgDefaultHomeRelativePath, pmgDefaultSandboxViolationCacheDir)
	assert.Equal(t, expected, Get().SandboxViolationCacheDir())
}

// userCacheBase returns the platform's user cache root the same way cacheDir()
// in config.go resolves it (sans the PMG_CACHE_DIR override).
func userCacheBase() (string, error) {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			base = os.Getenv("USERPROFILE")
		}
		return base, nil
	default:
		return os.UserCacheDir()
	}
}
