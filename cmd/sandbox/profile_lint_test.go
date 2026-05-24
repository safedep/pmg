package sandbox

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	pmgsandbox "github.com/safedep/pmg/sandbox"
)

func writeUserProfileLint(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name+".yml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}

func TestProfileLint_BuiltinClean(t *testing.T) {
	cmd := newProfileLintCommand(newTestRegistry(t, ""))
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"npm-restrictive"})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, stdout.String(), "Profile Lint")
}

func TestProfileLint_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	writeUserProfileLint(t, dir, "broad", `name: broad
description: broad profile
package_managers:
  - npm
filesystem:
  allow_read:
    - /**
  allow_write:
    - ${HOME}/**
`)

	cmd := newProfileLintCommand(newTestRegistry(t, dir))
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"broad", "--json"})

	err := cmd.Execute()
	// Lint surfaces warnings but no errors; exit should be zero without --strict.
	require.NoError(t, err)

	var report struct {
		Profile string                 `json:"profile"`
		Issues  []pmgsandbox.LintIssue `json:"issues"`
	}
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &report))
	assert.Equal(t, filepath.Join(dir, "broad.yml"), report.Profile)
	codes := map[string]int{}
	for _, i := range report.Issues {
		codes[i.Code]++
	}
	assert.Equal(t, 1, codes["broad.root_glob"])
	assert.Equal(t, 1, codes["broad.home_glob"])
}

func TestProfileLint_StrictFailsOnWarn(t *testing.T) {
	dir := t.TempDir()
	writeUserProfileLint(t, dir, "warn", `name: warn
description: warn profile
package_managers:
  - npm
filesystem:
  allow_read:
    - /**
`)

	cmd := newProfileLintCommand(newTestRegistry(t, dir))
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"warn", "--strict"})

	err := cmd.Execute()
	require.Error(t, err)
	fail, ok := err.(*lintFailError)
	require.True(t, ok, "expected *lintFailError, got %T", err)
	assert.Equal(t, ExitCodeLintFail, fail.ExitCode())
}

func TestProfileLint_NoStrictWarnSucceeds(t *testing.T) {
	dir := t.TempDir()
	writeUserProfileLint(t, dir, "warn", `name: warn
description: warn profile
package_managers:
  - npm
filesystem:
  allow_read:
    - /**
`)

	cmd := newProfileLintCommand(newTestRegistry(t, dir))
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"warn"})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, stdout.String(), "WARN")
}

func TestProfileLint_VerboseShowsInfo(t *testing.T) {
	dir := t.TempDir()
	writeUserProfileLint(t, dir, "dead", `name: dead
description: dead rule profile
package_managers:
  - npm
filesystem:
  allow_read:
    - ${HOME}/.cache/npm/**
    - ${HOME}/.cache/npm/foo
`)

	t.Run("default hides info", func(t *testing.T) {
		cmd := newProfileLintCommand(newTestRegistry(t, dir))
		var stdout bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"dead", "--json"})
		require.NoError(t, cmd.Execute())

		var report struct {
			Issues []pmgsandbox.LintIssue `json:"issues"`
		}
		require.NoError(t, json.Unmarshal(stdout.Bytes(), &report))
		for _, i := range report.Issues {
			assert.NotEqual(t, pmgsandbox.LintLevelInfo, i.Level)
		}
	})

	t.Run("verbose shows info", func(t *testing.T) {
		cmd := newProfileLintCommand(newTestRegistry(t, dir))
		var stdout bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"dead", "--json", "--verbose"})
		require.NoError(t, cmd.Execute())

		var report struct {
			Issues []pmgsandbox.LintIssue `json:"issues"`
		}
		require.NoError(t, json.Unmarshal(stdout.Bytes(), &report))
		foundInfo := false
		for _, i := range report.Issues {
			if i.Level == pmgsandbox.LintLevelInfo {
				foundInfo = true
			}
		}
		assert.True(t, foundInfo, "expected at least one info-level issue with --verbose")
	})
}

func TestProfileLint_UnknownProfile(t *testing.T) {
	cmd := newProfileLintCommand(newTestRegistry(t, ""))
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"does-not-exist"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Empty(t, stderr.String())
	assert.Contains(t, err.Error(), "not found")
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.NotFound, usefulErr.Code())
}

func TestProfileLintMissingTargetShowsUsage(t *testing.T) {
	cmd := newProfileLintCommand(newTestRegistry(t, ""))
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, stderr.String(), "accepts 1 arg(s), received 0")
	assert.Contains(t, stdout.String(), "Usage:")
	assert.Contains(t, stdout.String(), "lint <path|name> [flags]")
	assert.Contains(t, stdout.String(), "pmg sandbox profile lint npm-restrictive")
}

func TestProfileLint_InvalidYAMLReturnsInvalidArgument(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.yml")
	require.NoError(t, os.WriteFile(path, []byte("name: broken\npackage_managers:\n  - npm\n  invalid: : :\n"), 0o644))

	cmd := newProfileLintCommand(newTestRegistry(t, dir))
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"broken"})

	err := cmd.Execute()
	require.Error(t, err)
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.InvalidArgument, usefulErr.Code())
}

func TestProfileLint_LiteralPath(t *testing.T) {
	dir := t.TempDir()
	path := writeUserProfileLint(t, dir, "literal", `name: literal
description: literal
package_managers:
  - npm
filesystem:
  allow_read:
    - /tmp
`)

	// Use a registry without user dir — must fall through to the literal path branch.
	cmd := newProfileLintCommand(newTestRegistry(t, ""))
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{path, "--json"})

	require.NoError(t, cmd.Execute())
	var report struct {
		Profile string `json:"profile"`
	}
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &report))
	assert.Equal(t, path, report.Profile)
}
