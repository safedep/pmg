package sandbox

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmgsandbox "github.com/safedep/pmg/sandbox"
)

func newTestRegistry(t *testing.T, userDir string) registryFactory {
	t.Helper()
	return func() (pmgsandbox.ProfileRegistry, error) {
		opts := []pmgsandbox.RegistryOption{}
		if userDir != "" {
			opts = append(opts, pmgsandbox.WithUserProfileDir(userDir))
		}
		return pmgsandbox.NewProfileRegistry(opts...)
	}
}

func writeTestUserProfile(t *testing.T, dir, name string) {
	t.Helper()
	body := "name: " + name + `
description: user ` + name + `
package_managers:
  - npm
filesystem:
  allow_read:
    - /tmp
  allow_write:
    - /tmp
  deny_read: []
  deny_write: []
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, name+".yml"), []byte(body), 0o644))
}

func TestProfileListHuman(t *testing.T) {
	cmd := newProfileListCommand(newTestRegistry(t, ""))
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{})

	require.NoError(t, cmd.Execute())

	out := stdout.String()
	assert.Contains(t, out, "Sandbox Profiles")
	assert.Contains(t, out, "npm-restrictive")
	assert.Contains(t, out, "builtin")
}

func TestProfileListJSON(t *testing.T) {
	dir := t.TempDir()
	writeTestUserProfile(t, dir, "my-custom")

	cmd := newProfileListCommand(newTestRegistry(t, dir))
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--json"})

	require.NoError(t, cmd.Execute())

	var report jsonProfileListReport
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &report))
	require.NotEmpty(t, report.Profiles)

	var foundBuiltin, foundUser bool
	for _, p := range report.Profiles {
		if p.Source == "builtin" {
			foundBuiltin = true
		}
		if p.Source == "user" && p.Name == "my-custom" {
			foundUser = true
			assert.NotEmpty(t, p.Path)
		}
	}
	assert.True(t, foundBuiltin)
	assert.True(t, foundUser)
}

func TestProfileListShadowedTag(t *testing.T) {
	dir := t.TempDir()
	writeTestUserProfile(t, dir, "npm-restrictive")

	cmd := newProfileListCommand(newTestRegistry(t, dir))
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, stdout.String(), "SHADOWED")
}

func TestProfileListRejectsUnexpectedArgs(t *testing.T) {
	cmd := newProfileListCommand(newTestRegistry(t, ""))
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"extra"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, stderr.String(), "unknown command")
	assert.Contains(t, stdout.String(), "Usage:")
	assert.Contains(t, stdout.String(), "list [flags]")
	assert.Contains(t, stdout.String(), "pmg sandbox profile list")
}
