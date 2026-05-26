package sandbox

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func execProjectReset(t *testing.T, overlayDir, repoRoot string, args ...string) (string, string, error) {
	t.Helper()
	cmd := newProjectResetCommand(projectDeps{
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

func TestProjectReset_RequiresYes(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Clean(t.TempDir())
	_, err := pmgsandbox.SaveOverlay(dir, repo, &pmgsandbox.Overlay{
		Allow: []pmgsandbox.OverlayAllow{{Type: config.SandboxAllowExec, Value: "/x"}},
	})
	require.NoError(t, err)

	_, _, err = execProjectReset(t, dir, repo)
	require.Error(t, err)

	overlay, _, err := pmgsandbox.LoadOverlayForRepo(dir, repo)
	require.NoError(t, err)
	require.NotNil(t, overlay)
}

func TestProjectReset_WithYesDeletes(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Clean(t.TempDir())
	_, err := pmgsandbox.SaveOverlay(dir, repo, &pmgsandbox.Overlay{
		Allow: []pmgsandbox.OverlayAllow{{Type: config.SandboxAllowExec, Value: "/x"}},
	})
	require.NoError(t, err)

	stdout, _, err := execProjectReset(t, dir, repo, "--yes")
	require.NoError(t, err)
	assert.Contains(t, stdout, repo)
	assert.Contains(t, stdout, "Deleted")

	overlay, _, err := pmgsandbox.LoadOverlayForRepo(dir, repo)
	require.NoError(t, err)
	assert.Nil(t, overlay)
}

func TestProjectReset_MissingIsNoop(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Clean(t.TempDir())
	stdout, _, err := execProjectReset(t, dir, repo, "--yes")
	require.NoError(t, err)
	assert.Contains(t, stdout, "No project overlay")
}
