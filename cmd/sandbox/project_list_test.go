package sandbox

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/safedep/pmg/config"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func execProjectList(t *testing.T, overlayDir string, args ...string) (string, string, error) {
	t.Helper()
	cmd := newProjectListCommand(projectDeps{
		overlayDir: func() string { return overlayDir },
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestProjectList_Empty(t *testing.T) {
	dir := t.TempDir()
	stdout, _, err := execProjectList(t, dir)
	require.NoError(t, err)
	assert.Contains(t, stdout, "No project overlays")
}

func TestProjectList_Human(t *testing.T) {
	dir := t.TempDir()
	for _, repo := range []string{"/repo/a", "/repo/b"} {
		_, err := pmgsandbox.SaveOverlay(dir, repo, &pmgsandbox.Overlay{
			Allow: []pmgsandbox.OverlayAllow{{Type: config.SandboxAllowExec, Value: "/bin/x"}},
		})
		require.NoError(t, err)
	}

	stdout, _, err := execProjectList(t, dir)
	require.NoError(t, err)
	assert.Contains(t, stdout, "/repo/a")
	assert.Contains(t, stdout, "/repo/b")
}

func TestProjectList_JSON(t *testing.T) {
	dir := t.TempDir()
	for _, repo := range []string{"/repo/a", "/repo/b"} {
		_, err := pmgsandbox.SaveOverlay(dir, repo, &pmgsandbox.Overlay{
			Allow: []pmgsandbox.OverlayAllow{{Type: config.SandboxAllowExec, Value: "/bin/x"}},
		})
		require.NoError(t, err)
	}

	stdout, _, err := execProjectList(t, dir, "--json")
	require.NoError(t, err)
	var payload struct {
		Entries []struct {
			RepoRoot string `json:"repo_root"`
			Entries  int    `json:"entries"`
			Path     string `json:"path"`
		} `json:"entries"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &payload))
	require.Len(t, payload.Entries, 2)
	assert.Equal(t, "/repo/a", payload.Entries[0].RepoRoot)
	assert.Equal(t, 1, payload.Entries[0].Entries)
}

func TestProjectList_JSONEmpty(t *testing.T) {
	dir := t.TempDir()
	stdout, _, err := execProjectList(t, dir, "--json")
	require.NoError(t, err)
	var payload struct {
		Entries []any `json:"entries"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &payload))
	assert.NotNil(t, payload.Entries)
	assert.Empty(t, payload.Entries)
}
