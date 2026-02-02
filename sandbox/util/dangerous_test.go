package util

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetMandatoryDenyPatterns(t *testing.T) {
	t.Run("always blocks dangerous files", func(t *testing.T) {
		patterns := GetMandatoryDenyPatterns(false)

		// Should contain patterns for each dangerous file
		assert.Contains(t, patterns, "**/.env")
		assert.Contains(t, patterns, "**/.ssh")
		assert.Contains(t, patterns, "**/.aws")
		assert.Contains(t, patterns, "**/.gcloud")
		assert.Contains(t, patterns, "**/.kube")
		assert.Contains(t, patterns, "**/.gnupg")
		assert.Contains(t, patterns, "**/.docker/config.json")
	})

	t.Run("always blocks git hooks in CWD and HOME", func(t *testing.T) {
		cwd, err := os.Getwd()
		assert.NoError(t, err)

		home, err := os.UserHomeDir()
		assert.NoError(t, err)

		patterns := GetMandatoryDenyPatterns(false)

		// Should block git hooks in CWD
		assert.Contains(t, patterns, filepath.Join(cwd, ".git/hooks"))
		assert.Contains(t, patterns, filepath.Join(cwd, ".git/hooks/**"))

		// Should block git hooks in HOME
		assert.Contains(t, patterns, filepath.Join(home, ".git/hooks"))
		assert.Contains(t, patterns, filepath.Join(home, ".git/hooks/**"))
	})

	t.Run("blocks git config when allowGitConfig is false", func(t *testing.T) {
		cwd, err := os.Getwd()
		assert.NoError(t, err)

		home, err := os.UserHomeDir()
		assert.NoError(t, err)

		patterns := GetMandatoryDenyPatterns(false)

		// Should block git config in CWD and HOME
		assert.Contains(t, patterns, filepath.Join(cwd, ".git/config"))
		assert.Contains(t, patterns, filepath.Join(home, ".git/config"))
	})

	t.Run("allows git config when allowGitConfig is true", func(t *testing.T) {
		patterns := GetMandatoryDenyPatterns(true)

		// Should NOT block git config
		for _, pattern := range patterns {
			assert.NotContains(t, pattern, ".git/config")
		}
	})

	t.Run("includes CWD-relative patterns", func(t *testing.T) {
		cwd, err := os.Getwd()
		assert.NoError(t, err)

		patterns := GetMandatoryDenyPatterns(false)

		// Should include absolute paths in CWD
		assert.Contains(t, patterns, filepath.Join(cwd, ".env"))
		assert.Contains(t, patterns, filepath.Join(cwd, ".ssh"))
		assert.Contains(t, patterns, filepath.Join(cwd, ".git/hooks"))
	})

	t.Run("includes HOME-relative patterns", func(t *testing.T) {
		home, err := os.UserHomeDir()
		assert.NoError(t, err)

		patterns := GetMandatoryDenyPatterns(false)

		// Should include absolute paths in HOME
		assert.Contains(t, patterns, filepath.Join(home, ".env"))
		assert.Contains(t, patterns, filepath.Join(home, ".ssh"))
		assert.Contains(t, patterns, filepath.Join(home, ".aws"))
	})

	t.Run("includes glob patterns for env variants", func(t *testing.T) {
		patterns := GetMandatoryDenyPatterns(false)

		// Should include pattern for .env.* files
		assert.Contains(t, patterns, "**/.env.*")
	})

	t.Run("does not use global globs for git operations", func(t *testing.T) {
		patterns := GetMandatoryDenyPatterns(false)

		// Should NOT contain global globs for git hooks/config
		// This allows legitimate git operations in temp directories (e.g., npx cloning repos)
		assert.NotContains(t, patterns, "**/.git/hooks")
		assert.NotContains(t, patterns, "**/.git/hooks/**")
		assert.NotContains(t, patterns, "**/.git/config")
	})
}
