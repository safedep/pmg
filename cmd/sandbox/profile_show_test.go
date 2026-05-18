package sandbox

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/safedep/pmg/usefulerror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProfileShowRaw(t *testing.T) {
	cmd := newProfileShowCommand(newTestRegistry(t, ""))
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"npm-restrictive"})

	require.NoError(t, cmd.Execute())

	out := stdout.String()
	assert.Contains(t, out, "name: npm-restrictive")
	assert.Contains(t, out, "${CWD}", "raw output should preserve placeholders")
}

func TestProfileShowResolved(t *testing.T) {
	cmd := newProfileShowCommand(newTestRegistry(t, ""))
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"npm-restrictive", "--resolved", "--cwd", "/work", "--home", "/h"})

	require.NoError(t, cmd.Execute())

	out := stdout.String()
	assert.NotContains(t, out, "${CWD}")
	assert.NotContains(t, out, "${HOME}")
	assert.Contains(t, out, "/work")
	assert.Contains(t, out, "/h")
}

func TestProfileShowJSONRaw(t *testing.T) {
	cmd := newProfileShowCommand(newTestRegistry(t, ""))
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"npm-restrictive", "--json"})

	require.NoError(t, cmd.Execute())

	var report map[string]any
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &report))
	assert.Equal(t, "npm-restrictive", report["name"])
	assert.Equal(t, "builtin", report["source"])
	assert.Contains(t, report["yaml"].(string), "name: npm-restrictive")
}

func TestProfileShowUnknownDriver(t *testing.T) {
	cmd := newProfileShowCommand(newTestRegistry(t, ""))
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"npm-restrictive", "--driver", "bogus"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Empty(t, stderr.String())
	assert.Contains(t, err.Error(), "unknown driver")
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, usefulerror.ErrCodeInvalidArgument, usefulErr.Code())
}

func TestProfileShowUnknownProfileReturnsNotFound(t *testing.T) {
	cmd := newProfileShowCommand(newTestRegistry(t, ""))
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"does-not-exist"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Empty(t, stdout.String())
	assert.Empty(t, stderr.String())
	assert.Contains(t, err.Error(), "not found")
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, usefulerror.ErrCodeNotFound, usefulErr.Code())
}

func TestProfileShowMissingNameShowsUsage(t *testing.T) {
	cmd := newProfileShowCommand(newTestRegistry(t, ""))
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, stderr.String(), "accepts 1 arg(s), received 0")
	assert.Contains(t, stdout.String(), "Usage:")
	assert.Contains(t, stdout.String(), "show <name> [flags]")
	assert.Contains(t, stdout.String(), "pmg sandbox profile show npm-restrictive --resolved")
}

func TestProfileShowDriverNative(t *testing.T) {
	cmd := newProfileShowCommand(newTestRegistry(t, ""))
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})

	driver := ""
	switch runtime.GOOS {
	case "darwin":
		driver = "seatbelt"
	case "linux":
		driver = "bubblewrap"
	default:
		t.Skipf("no native driver for %s", runtime.GOOS)
	}

	cmd.SetArgs([]string{"npm-restrictive", "--driver", driver})
	require.NoError(t, cmd.Execute())
	assert.NotEmpty(t, strings.TrimSpace(stdout.String()))
}

func TestProfileShowDriverNonNativeErrors(t *testing.T) {
	cmd := newProfileShowCommand(newTestRegistry(t, ""))
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	driver := ""
	switch runtime.GOOS {
	case "darwin":
		driver = "bubblewrap"
	case "linux":
		driver = "seatbelt"
	default:
		t.Skipf("no non-native driver to test on %s", runtime.GOOS)
	}

	cmd.SetArgs([]string{"npm-restrictive", "--driver", driver})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Empty(t, stderr.String())
	assert.Contains(t, err.Error(), "not available")
}
