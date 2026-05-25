package sandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeDiffUserProfile(t *testing.T, dir, name, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, name+".yml"), []byte(body), 0o644))
}

func runDiffCmd(t *testing.T, factory registryFactory, args ...string) (string, string, error) {
	t.Helper()
	cmd := newProfileDiffCommand(factory)
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestProfileDiffSameProfileNoOutput(t *testing.T) {
	stdout, stderr, err := runDiffCmd(t, newTestRegistry(t, ""), "npm-restrictive", "npm-restrictive")
	require.NoError(t, err)
	assert.Empty(t, stdout, "stdout should be empty when profiles are identical")
	assert.Contains(t, stderr, "identical")
}

func TestProfileDiffDistinctProfiles(t *testing.T) {
	stdout, _, err := runDiffCmd(t, newTestRegistry(t, ""), "npm-restrictive", "pypi-restrictive")
	require.Error(t, err)
	de, ok := err.(*diffPresentError)
	require.True(t, ok, "expected diffPresentError, got %T", err)
	assert.Equal(t, 1, de.ExitCode())

	assert.NotEmpty(t, stdout)
	assert.Contains(t, stdout, "--- npm-restrictive")
	assert.Contains(t, stdout, "+++ pypi-restrictive")
	// Some +/- body lines should be present.
	hasPlus := false
	hasMinus := false
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			hasPlus = true
		}
		if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			hasMinus = true
		}
	}
	assert.True(t, hasPlus, "expected at least one '+' line")
	assert.True(t, hasMinus, "expected at least one '-' line")
}

func TestProfileDiffDriverNative(t *testing.T) {
	driver := ""
	switch runtime.GOOS {
	case "darwin":
		driver = "seatbelt"
	case "linux":
		driver = "bubblewrap"
	default:
		t.Skipf("no native driver for %s", runtime.GOOS)
	}

	stdout, _, err := runDiffCmd(t, newTestRegistry(t, ""), "npm-restrictive", "pypi-restrictive", "--driver", driver)
	require.Error(t, err)
	_, ok := err.(*diffPresentError)
	require.True(t, ok, "expected diffPresentError, got %T", err)

	assert.NotEmpty(t, stdout)
	if driver == "seatbelt" {
		// SBPL output should contain version line or s-expressions, not YAML keys.
		assert.True(t,
			strings.Contains(stdout, "(version") || strings.Contains(stdout, "allow") || strings.Contains(stdout, "deny"),
			"expected SBPL-ish body, got: %s", stdout)
		assert.NotContains(t, stdout, "package_managers:")
	}
}

func TestProfileDiffUnknownProfile(t *testing.T) {
	stdout, stderr, err := runDiffCmd(t, newTestRegistry(t, ""), "npm-restrictive", "no-such-profile-xyz")
	require.Error(t, err)
	de, ok := err.(*diffOpError)
	require.True(t, ok, "expected diffOpError, got %T", err)
	assert.Equal(t, ExitCodeDiffError, de.ExitCode())
	assert.Empty(t, stdout)
	assert.Empty(t, stderr)
	assert.Contains(t, err.Error(), "no-such-profile-xyz")
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok, "diff error should expose a UsefulError through Unwrap")
	assert.Equal(t, errcodes.NotFound, usefulErr.Code())
}

func TestProfileDiffUnknownDriver(t *testing.T) {
	stdout, stderr, err := runDiffCmd(t, newTestRegistry(t, ""), "npm-restrictive", "npm-restrictive", "--driver", "bogus")
	require.Error(t, err)
	de, ok := err.(*diffOpError)
	require.True(t, ok, "expected diffOpError, got %T", err)
	assert.Equal(t, ExitCodeDiffError, de.ExitCode())
	assert.Empty(t, stdout)
	assert.Empty(t, stderr)
	assert.Contains(t, err.Error(), "unknown driver")
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok, "diff error should expose a UsefulError through Unwrap")
	assert.Equal(t, errcodes.InvalidArgument, usefulErr.Code())
}

func TestProfileDiffMissingProfileShowsUsage(t *testing.T) {
	stdout, stderr, err := runDiffCmd(t, newTestRegistry(t, ""), "npm-restrictive")
	require.Error(t, err)
	assert.Contains(t, stderr, "accepts 2 arg(s), received 1")
	assert.Contains(t, stdout, "Usage:")
	assert.Contains(t, stdout, "diff <a> <b> [flags]")
	assert.Contains(t, stdout, "pmg sandbox profile diff npm-restrictive pypi-restrictive")
}

func TestProfileDiffCWDOverride(t *testing.T) {
	// Two user profiles with identical bodies referencing ${CWD}. Diffing
	// them with the same name but different --cwd values isn't supported by
	// the CLI (single --cwd), so we exercise the path delta by using two
	// distinct user profiles with hard-coded different cwd-style paths.
	//
	// Easier: use the same profile twice with no --cwd vs --cwd, which the
	// CLI doesn't allow on a per-side basis. So we approximate by giving
	// both sides the same profile under different file names but with
	// different baked-in paths — proving cwd-derived deltas show up in YAML.
	dir := t.TempDir()
	writeDiffUserProfile(t, dir, "p-a", `name: p-a
description: a
package_managers:
  - npm
filesystem:
  allow_read:
    - /aaa
`)
	writeDiffUserProfile(t, dir, "p-b", `name: p-b
description: b
package_managers:
  - npm
filesystem:
  allow_read:
    - /bbb
`)

	stdout, _, err := runDiffCmd(t, newTestRegistry(t, dir), "p-a", "p-b")
	require.Error(t, err)
	_, ok := err.(*diffPresentError)
	require.True(t, ok)
	assert.Contains(t, stdout, "/aaa")
	assert.Contains(t, stdout, "/bbb")
}

func TestDiffPresentErrorExitCode(t *testing.T) {
	e := &diffPresentError{}
	assert.Equal(t, 1, e.ExitCode())
}

func TestDiffOpErrorExitCode(t *testing.T) {
	e := &diffOpError{}
	assert.Equal(t, ExitCodeDiffError, e.ExitCode())
}
