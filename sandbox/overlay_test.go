package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func evalPath(t *testing.T, p string) string {
	t.Helper()
	v, err := filepath.EvalSymlinks(p)
	require.NoError(t, err)
	return v
}

func TestOverlayResolveRepoRootGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo := t.TempDir()
	require.NoError(t, exec.Command("git", "-C", repo, "init", "-q").Run())
	sub := filepath.Join(repo, "pkg", "deep")
	require.NoError(t, os.MkdirAll(sub, 0o755))

	got, err := ResolveRepoRoot(sub)
	require.NoError(t, err)
	assert.Equal(t, evalPath(t, repo), evalPath(t, got))
}

func TestOverlayResolveRepoRootNonGitFallsBackToCWD(t *testing.T) {
	dir := t.TempDir()
	got, err := ResolveRepoRoot(dir)
	require.NoError(t, err)
	assert.Equal(t, evalPath(t, dir), evalPath(t, got))
}

func TestOverlayResolveRepoRootEmpty(t *testing.T) {
	_, err := ResolveRepoRoot("")
	assert.Error(t, err)
}

func TestOverlaySaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	repo := "/repo/example"

	in := &Overlay{
		Allow: []OverlayAllow{
			{Type: config.SandboxAllowWrite, Value: "/repo/example/.astro"},
			{Type: config.SandboxAllowNetBind, Value: "localhost:4321"},
		},
	}
	path, err := SaveOverlay(dir, repo, in)
	require.NoError(t, err)
	assert.FileExists(t, path)
	assert.Equal(t, OverlaySchemaVersion, in.SchemaVersion)
	assert.Equal(t, repo, in.RepoRoot)
	assert.False(t, in.UpdatedAt.IsZero())
	assert.False(t, in.CreatedAt.IsZero())

	loaded, loadedPath, err := LoadOverlayForRepo(dir, repo)
	require.NoError(t, err)
	assert.Equal(t, path, loadedPath)
	require.NotNil(t, loaded)
	assert.Equal(t, repo, loaded.RepoRoot)
	assert.ElementsMatch(t, in.Allow, loaded.Allow)
}

func TestOverlaySavePreservesCreatedAt(t *testing.T) {
	dir := t.TempDir()
	repo := "/repo/example"

	first := &Overlay{Allow: []OverlayAllow{{Type: config.SandboxAllowExec, Value: "/bin/sh"}}}
	_, err := SaveOverlay(dir, repo, first)
	require.NoError(t, err)
	createdAt := first.CreatedAt

	second := &Overlay{Allow: []OverlayAllow{{Type: config.SandboxAllowExec, Value: "/bin/zsh"}}}
	_, err = SaveOverlay(dir, repo, second)
	require.NoError(t, err)
	assert.Equal(t, createdAt, second.CreatedAt)
}

func TestLoadOverlayForRepoMissingReturnsNil(t *testing.T) {
	dir := t.TempDir()
	overlay, path, err := LoadOverlayForRepo(dir, "/nope")
	require.NoError(t, err)
	assert.Nil(t, overlay)
	assert.Empty(t, path)
}

func TestLoadOverlayForRepoEmptyArgsReturnsNil(t *testing.T) {
	overlay, _, err := LoadOverlayForRepo("", "/repo")
	require.NoError(t, err)
	assert.Nil(t, overlay)

	overlay, _, err = LoadOverlayForRepo(t.TempDir(), "")
	require.NoError(t, err)
	assert.Nil(t, overlay)
}

func TestOverlayAddDedupsByTypeAndValue(t *testing.T) {
	o := &Overlay{}
	assert.True(t, o.Add(OverlayAllow{Type: config.SandboxAllowWrite, Value: "/a"}))
	assert.False(t, o.Add(OverlayAllow{Type: config.SandboxAllowWrite, Value: "/a"}))
	assert.True(t, o.Add(OverlayAllow{Type: config.SandboxAllowRead, Value: "/a"}))
	assert.Len(t, o.Allow, 2)
}

func TestOverlayToAllowOverrides(t *testing.T) {
	o := &Overlay{
		Allow: []OverlayAllow{
			{Type: config.SandboxAllowWrite, Value: "/a"},
			{Type: config.SandboxAllowNetBind, Value: "localhost:1234"},
		},
	}
	got := o.ToAllowOverrides()
	require.Len(t, got, 2)
	assert.Equal(t, config.SandboxAllowWrite, got[0].Type)
	assert.Equal(t, "/a", got[0].Value)
	assert.Equal(t, "write=/a", got[0].Raw)
	assert.Equal(t, config.SandboxAllowNetBind, got[1].Type)
	assert.Equal(t, "net-bind=localhost:1234", got[1].Raw)
}

func TestDeleteOverlayForRepoIdempotent(t *testing.T) {
	dir := t.TempDir()
	repo := "/repo/x"
	_, err := SaveOverlay(dir, repo, &Overlay{Allow: []OverlayAllow{{Type: config.SandboxAllowExec, Value: "/bin/x"}}})
	require.NoError(t, err)
	require.NoError(t, DeleteOverlayForRepo(dir, repo))
	// Second call is a no-op.
	require.NoError(t, DeleteOverlayForRepo(dir, repo))
}

func TestListOverlaysReturnsAllSorted(t *testing.T) {
	dir := t.TempDir()
	repos := []string{"/repo/c", "/repo/a", "/repo/b"}
	for _, r := range repos {
		_, err := SaveOverlay(dir, r, &Overlay{Allow: []OverlayAllow{{Type: config.SandboxAllowExec, Value: "/bin/x"}}})
		require.NoError(t, err)
	}
	listed, err := ListOverlays(dir)
	require.NoError(t, err)
	require.Len(t, listed, 3)
	assert.Equal(t, "/repo/a", listed[0].Overlay.RepoRoot)
	assert.Equal(t, "/repo/b", listed[1].Overlay.RepoRoot)
	assert.Equal(t, "/repo/c", listed[2].Overlay.RepoRoot)
}

func TestListOverlaysMissingDirIsEmpty(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does", "not", "exist")
	listed, err := ListOverlays(dir)
	require.NoError(t, err)
	assert.Empty(t, listed)
}

func TestListOverlaysSkipsCorruptFiles(t *testing.T) {
	dir := t.TempDir()
	_, err := SaveOverlay(dir, "/repo/a", &Overlay{Allow: []OverlayAllow{{Type: config.SandboxAllowExec, Value: "/bin/x"}}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "garbage.yml"), []byte("{not valid yaml]"), 0o644))

	listed, err := ListOverlays(dir)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, "/repo/a", listed[0].Overlay.RepoRoot)
}
