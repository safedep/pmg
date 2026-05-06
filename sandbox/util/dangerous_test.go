package util

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func emptyOpts() MandatoryDenyOptions {
	return MandatoryDenyOptions{AllowGitConfig: false}
}

func TestGetMandatoryDenyPatterns_NoAllowList(t *testing.T) {
	t.Run("blocks dangerous file globs on both sides", func(t *testing.T) {
		r := GetMandatoryDenyPatterns(emptyOpts())

		for _, p := range []string{
			"**/.env", "**/.env.*", "**/.ssh", "**/.aws", "**/.azure",
			"**/.gcloud", "**/.config/gcloud", "**/.kube", "**/.gnupg",
			"**/.docker/config.json", "**/.netrc", "**/.git-credentials",
			"**/.pgpass", "**/.config/gh",
		} {
			assert.Contains(t, r.DenyRead, p, "DenyRead missing %s", p)
			assert.Contains(t, r.DenyWrite, p, "DenyWrite missing %s", p)
		}

		assert.Empty(t, r.SuppressedRead)
		assert.Empty(t, r.SuppressedWrite)
	})

	t.Run("blocks git hooks unconditionally on both sides", func(t *testing.T) {
		cwd, err := os.Getwd()
		require.NoError(t, err)
		home, err := os.UserHomeDir()
		require.NoError(t, err)

		r := GetMandatoryDenyPatterns(emptyOpts())

		for _, p := range []string{
			filepath.Join(cwd, ".git/hooks"),
			filepath.Join(cwd, ".git/hooks/**"),
			filepath.Join(home, ".git/hooks"),
			filepath.Join(home, ".git/hooks/**"),
		} {
			assert.Contains(t, r.DenyRead, p)
			assert.Contains(t, r.DenyWrite, p)
		}
	})

	t.Run("blocks git config when AllowGitConfig is false", func(t *testing.T) {
		cwd, err := os.Getwd()
		require.NoError(t, err)
		home, err := os.UserHomeDir()
		require.NoError(t, err)

		r := GetMandatoryDenyPatterns(MandatoryDenyOptions{AllowGitConfig: false})

		assert.Contains(t, r.DenyWrite, filepath.Join(cwd, ".git/config"))
		assert.Contains(t, r.DenyWrite, filepath.Join(home, ".git/config"))
		assert.Contains(t, r.DenyRead, filepath.Join(cwd, ".git/config"))
		assert.Contains(t, r.DenyRead, filepath.Join(home, ".git/config"))
	})

	t.Run("omits git config when AllowGitConfig is true", func(t *testing.T) {
		cwd, err := os.Getwd()
		require.NoError(t, err)
		home, err := os.UserHomeDir()
		require.NoError(t, err)

		r := GetMandatoryDenyPatterns(MandatoryDenyOptions{AllowGitConfig: true})

		cwdGitConfig := filepath.Join(cwd, ".git/config")
		homeGitConfig := filepath.Join(home, ".git/config")

		assert.NotContains(t, r.DenyRead, cwdGitConfig)
		assert.NotContains(t, r.DenyRead, homeGitConfig)
		assert.NotContains(t, r.DenyWrite, cwdGitConfig)
		assert.NotContains(t, r.DenyWrite, homeGitConfig)
	})

	t.Run("includes CWD-absolute and HOME-absolute forms", func(t *testing.T) {
		cwd, err := os.Getwd()
		require.NoError(t, err)
		home, err := os.UserHomeDir()
		require.NoError(t, err)

		r := GetMandatoryDenyPatterns(emptyOpts())

		assert.Contains(t, r.DenyRead, filepath.Join(cwd, ".env"))
		assert.Contains(t, r.DenyRead, filepath.Join(home, ".env"))
		assert.Contains(t, r.DenyWrite, filepath.Join(cwd, ".aws"))
		assert.Contains(t, r.DenyWrite, filepath.Join(home, ".aws"))
	})

	t.Run("does not use global globs for git operations", func(t *testing.T) {
		r := GetMandatoryDenyPatterns(emptyOpts())

		for _, side := range [][]string{r.DenyRead, r.DenyWrite} {
			assert.NotContains(t, side, "**/.git/hooks")
			assert.NotContains(t, side, "**/.git/hooks/**")
			assert.NotContains(t, side, "**/.git/config")
		}
	})
}

func TestGetMandatoryDenyPatterns_Suppression(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	cwdEnv := filepath.Join(cwd, ".env")
	homeEnv := filepath.Join(home, ".env")
	globEnv := filepath.Join("**", ".env")
	homeAws := filepath.Join(home, ".aws")
	cwdGitConfig := filepath.Join(cwd, ".git/config")

	t.Run("CWD-absolute form suppresses CWD form and glob form on same direction", func(t *testing.T) {
		r := GetMandatoryDenyPatterns(MandatoryDenyOptions{
			AllowRead: []string{cwdEnv},
		})

		assert.NotContains(t, r.DenyRead, cwdEnv)
		assert.Contains(t, r.SuppressedRead, cwdEnv)

		assert.NotContains(t, r.DenyRead, globEnv)
		assert.Contains(t, r.SuppressedRead, globEnv)

		assert.Contains(t, r.DenyRead, homeEnv)

		assert.Contains(t, r.DenyWrite, cwdEnv)
		assert.Contains(t, r.DenyWrite, globEnv)
		assert.Contains(t, r.DenyWrite, homeEnv)
		assert.Empty(t, r.SuppressedWrite)
	})

	t.Run("HOME-absolute form suppresses HOME form and glob form on same direction", func(t *testing.T) {
		r := GetMandatoryDenyPatterns(MandatoryDenyOptions{
			AllowRead: []string{homeAws},
		})

		homeAwsGlob := filepath.Join("**", ".aws")
		cwdAws := filepath.Join(cwd, ".aws")

		assert.NotContains(t, r.DenyRead, homeAws)
		assert.Contains(t, r.SuppressedRead, homeAws)

		assert.NotContains(t, r.DenyRead, homeAwsGlob)
		assert.Contains(t, r.SuppressedRead, homeAwsGlob)

		assert.Contains(t, r.DenyRead, cwdAws)
	})

	t.Run("glob form suppressed only when listed", func(t *testing.T) {
		r := GetMandatoryDenyPatterns(MandatoryDenyOptions{
			AllowRead: []string{globEnv},
		})

		assert.NotContains(t, r.DenyRead, globEnv)
		assert.Contains(t, r.SuppressedRead, globEnv)

		assert.Contains(t, r.DenyRead, cwdEnv)
		assert.Contains(t, r.DenyRead, homeEnv)
	})

	t.Run("read-side suppression does not affect write side", func(t *testing.T) {
		r := GetMandatoryDenyPatterns(MandatoryDenyOptions{
			AllowRead:  []string{cwdEnv},
			AllowWrite: []string{},
		})

		assert.NotContains(t, r.DenyRead, cwdEnv)
		assert.Contains(t, r.DenyWrite, cwdEnv)
	})

	t.Run("write-side suppression does not affect read side", func(t *testing.T) {
		r := GetMandatoryDenyPatterns(MandatoryDenyOptions{
			AllowWrite: []string{cwdEnv},
		})

		assert.NotContains(t, r.DenyWrite, cwdEnv)
		assert.Contains(t, r.DenyRead, cwdEnv)
	})

	t.Run("broad glob does NOT suppress", func(t *testing.T) {
		broad := filepath.Join(cwd, "**")
		r := GetMandatoryDenyPatterns(MandatoryDenyOptions{
			AllowRead: []string{broad},
		})

		assert.Empty(t, r.SuppressedRead)
		assert.Contains(t, r.DenyRead, cwdEnv)
	})

	t.Run("relative path in allow list does NOT suppress absolute form", func(t *testing.T) {
		r := GetMandatoryDenyPatterns(MandatoryDenyOptions{
			AllowRead: []string{".env"}, // post-Clean stays as ".env"
		})

		assert.Contains(t, r.DenyRead, cwdEnv)
		assert.Empty(t, r.SuppressedRead)
	})

	t.Run("git config CWD form suppressible via allow_write", func(t *testing.T) {
		r := GetMandatoryDenyPatterns(MandatoryDenyOptions{
			AllowGitConfig: false,
			AllowWrite:     []string{cwdGitConfig},
		})

		assert.NotContains(t, r.DenyWrite, cwdGitConfig)
		assert.Contains(t, r.SuppressedWrite, cwdGitConfig)
	})

	t.Run("git hooks NEVER suppressed", func(t *testing.T) {
		cwdHooks := filepath.Join(cwd, ".git/hooks")
		cwdHooksGlob := filepath.Join(cwd, ".git/hooks/**")
		homeHooks := filepath.Join(home, ".git/hooks")
		homeHooksGlob := filepath.Join(home, ".git/hooks/**")

		hookPaths := []string{cwdHooks, cwdHooksGlob, homeHooks, homeHooksGlob}

		r := GetMandatoryDenyPatterns(MandatoryDenyOptions{
			AllowRead:  hookPaths,
			AllowWrite: hookPaths,
		})

		for _, p := range hookPaths {
			assert.Contains(t, r.DenyRead, p)
			assert.Contains(t, r.DenyWrite, p)
			assert.NotContains(t, r.SuppressedRead, p)
			assert.NotContains(t, r.SuppressedWrite, p)
		}
	})

	t.Run("multiple suppressions accumulate", func(t *testing.T) {
		r := GetMandatoryDenyPatterns(MandatoryDenyOptions{
			AllowRead:  []string{cwdEnv, globEnv},
			AllowWrite: []string{cwdEnv},
		})

		// AllowWrite lists only cwdEnv; the absolute form auto-suppresses the
		// **/.env glob on that side too.
		assert.ElementsMatch(t, []string{cwdEnv, globEnv}, r.SuppressedRead)
		assert.ElementsMatch(t, []string{cwdEnv, globEnv}, r.SuppressedWrite)
	})
}
