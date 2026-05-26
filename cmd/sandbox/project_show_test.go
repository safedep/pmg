package sandbox

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func execProjectShow(t *testing.T, overlayDir, repoRoot string, args ...string) (string, string, error) {
	t.Helper()
	cmd := newProjectShowCommand(projectDeps{
		overlayDir: func() string { return overlayDir },
		repoRoot:   func() (string, error) { return repoRoot, nil },
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestProjectShow_Empty(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Clean(t.TempDir())
	stdout, _, err := execProjectShow(t, dir, repo)
	require.NoError(t, err)
	assert.Contains(t, stdout, repo)
	assert.Contains(t, stdout, "No project overlay")
}

func TestProjectShow_WithEntries(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Clean(t.TempDir())
	_, err := pmgsandbox.SaveOverlay(dir, repo, &pmgsandbox.Overlay{
		Allow: []pmgsandbox.OverlayAllow{{Type: config.SandboxAllowWrite, Value: "/repo/.astro"}},
	})
	require.NoError(t, err)

	stdout, _, err := execProjectShow(t, dir, repo)
	require.NoError(t, err)
	assert.Contains(t, stdout, repo)
	assert.Contains(t, stdout, "write")
	assert.Contains(t, stdout, "/repo/.astro")
}

func TestProjectShow_JSON(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Clean(t.TempDir())
	_, err := pmgsandbox.SaveOverlay(dir, repo, &pmgsandbox.Overlay{
		Allow: []pmgsandbox.OverlayAllow{{Type: config.SandboxAllowExec, Value: "/usr/bin/sh"}},
	})
	require.NoError(t, err)

	stdout, _, err := execProjectShow(t, dir, repo, "--json")
	require.NoError(t, err)
	var payload struct {
		RepoRoot string `json:"repo_root"`
		Path     string `json:"path"`
		Allow    []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"allow"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &payload))
	assert.Equal(t, repo, payload.RepoRoot)
	assert.NotEmpty(t, payload.Path)
	require.Len(t, payload.Allow, 1)
	assert.Equal(t, "exec", payload.Allow[0].Type)
	assert.Equal(t, "/usr/bin/sh", payload.Allow[0].Value)
}

func TestProjectShow_JSONEmpty(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Clean(t.TempDir())
	stdout, _, err := execProjectShow(t, dir, repo, "--json")
	require.NoError(t, err)
	var payload struct {
		Allow []any `json:"allow"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &payload))
	assert.NotNil(t, payload.Allow)
	assert.Empty(t, payload.Allow)
}
