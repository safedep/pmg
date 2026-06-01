package sandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type allowDeps struct {
	overlayDir string
	repoRoot   string
	cache      *pmgsandbox.ViolationCache
}

func newAllowDeps(t *testing.T) *allowDeps {
	t.Helper()
	return &allowDeps{
		overlayDir: t.TempDir(),
		repoRoot:   filepath.Clean(t.TempDir()),
		cache:      pmgsandbox.NewViolationCache(t.TempDir()),
	}
}

func runAllowCmd(t *testing.T, deps *allowDeps, args ...string) (string, string, error) {
	t.Helper()
	cmd := newAllowCommand(allowFactory{
		overlayDir: func() string { return deps.overlayDir },
		repoRoot:   func() (string, error) { return deps.repoRoot, nil },
		cache:      func() *pmgsandbox.ViolationCache { return deps.cache },
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestAllow_PositionalSaved(t *testing.T) {
	deps := newAllowDeps(t)
	stdout, stderr, err := runAllowCmd(t, deps, "net-bind=localhost:4321")
	require.NoError(t, err, "stderr: %s", stderr)
	assert.Contains(t, stdout, "Saved 1 allowance")

	overlay, _, err := pmgsandbox.LoadOverlayForRepo(deps.overlayDir, deps.repoRoot)
	require.NoError(t, err)
	require.NotNil(t, overlay)
	require.Len(t, overlay.Allow, 1)
	assert.Equal(t, config.SandboxAllowNetBind, overlay.Allow[0].Type)
	assert.Equal(t, "localhost:4321", overlay.Allow[0].Value)
}

func TestAllow_LastAllPromotesFromCache(t *testing.T) {
	deps := newAllowDeps(t)
	writeTarget := filepath.Join(deps.repoRoot, ".astro")
	execTarget := "/usr/bin/sh"
	report := &pmgsandbox.ViolationReport{
		SandboxName: pmgsandbox.DriverSeatbelt,
		Violations: []pmgsandbox.Violation{
			{Kind: pmgsandbox.ViolationKindFSWrite, Target: writeTarget},
			{Kind: pmgsandbox.ViolationKindExec, Target: execTarget},
		},
	}
	_, err := deps.cache.Write(report)
	require.NoError(t, err)

	_, stderr, err := runAllowCmd(t, deps, "--last", "--all")
	require.NoError(t, err, "stderr: %s", stderr)

	overlay, _, err := pmgsandbox.LoadOverlayForRepo(deps.overlayDir, deps.repoRoot)
	require.NoError(t, err)
	require.NotNil(t, overlay)
	assert.ElementsMatch(t, []pmgsandbox.OverlayAllow{
		{Type: config.SandboxAllowWrite, Value: writeTarget},
		{Type: config.SandboxAllowExec, Value: execTarget},
	}, overlay.Allow)
}

func TestAllow_LastPromotesPrimaryOnly(t *testing.T) {
	deps := newAllowDeps(t)
	writeTarget := filepath.Join(deps.repoRoot, ".astro")
	execTarget := "/usr/bin/sh"
	report := &pmgsandbox.ViolationReport{
		SandboxName: pmgsandbox.DriverSeatbelt,
		Violations: []pmgsandbox.Violation{
			{Kind: pmgsandbox.ViolationKindFSWrite, Target: writeTarget},
			{Kind: pmgsandbox.ViolationKindExec, Target: execTarget},
		},
	}
	_, err := deps.cache.Write(report)
	require.NoError(t, err)

	_, _, err = runAllowCmd(t, deps, "--last")
	require.NoError(t, err)

	overlay, _, err := pmgsandbox.LoadOverlayForRepo(deps.overlayDir, deps.repoRoot)
	require.NoError(t, err)
	require.NotNil(t, overlay)
	require.Len(t, overlay.Allow, 1)
}

func TestAllow_LastNoCacheErrors(t *testing.T) {
	deps := newAllowDeps(t)
	_, _, err := runAllowCmd(t, deps, "--last")
	require.Error(t, err)
}

func TestAllow_RefusesSensitiveTargetWithoutForce(t *testing.T) {
	deps := newAllowDeps(t)
	secret := filepath.Join(deps.repoRoot, ".env")
	_, _, err := runAllowCmd(t, deps, "read="+secret)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sensitive target")

	overlay, _, err := pmgsandbox.LoadOverlayForRepo(deps.overlayDir, deps.repoRoot)
	require.NoError(t, err)
	assert.Nil(t, overlay)
}

func TestAllow_SensitiveTargetWithForceSaves(t *testing.T) {
	deps := newAllowDeps(t)
	secret := filepath.Join(deps.repoRoot, ".env")
	_, _, err := runAllowCmd(t, deps, "--force", "read="+secret)
	require.NoError(t, err)
	overlay, _, err := pmgsandbox.LoadOverlayForRepo(deps.overlayDir, deps.repoRoot)
	require.NoError(t, err)
	require.NotNil(t, overlay)
	assert.Len(t, overlay.Allow, 1)
}

func TestAllow_Dedupes(t *testing.T) {
	deps := newAllowDeps(t)
	_, _, err := runAllowCmd(t, deps, "exec=/usr/bin/sh")
	require.NoError(t, err)
	stdout, _, err := runAllowCmd(t, deps, "exec=/usr/bin/sh")
	require.NoError(t, err)
	assert.Contains(t, stdout, "No new allowances")

	overlay, _, err := pmgsandbox.LoadOverlayForRepo(deps.overlayDir, deps.repoRoot)
	require.NoError(t, err)
	require.NotNil(t, overlay)
	assert.Len(t, overlay.Allow, 1)
}

func TestAllow_NothingToSaveErrors(t *testing.T) {
	deps := newAllowDeps(t)
	_, _, err := runAllowCmd(t, deps)
	require.Error(t, err)
}

func TestAllow_AllWithoutLastErrors(t *testing.T) {
	deps := newAllowDeps(t)
	_, _, err := runAllowCmd(t, deps, "--all", "exec=/usr/bin/sh")
	require.Error(t, err)
}

func TestAllow_InvalidPositionalRejected(t *testing.T) {
	deps := newAllowDeps(t)
	_, _, err := runAllowCmd(t, deps, "garbage")
	require.Error(t, err)
}

func TestAllow_RefusedUnderLockdown(t *testing.T) {
	deps := newAllowDeps(t)
	cmd := newAllowCommand(allowFactory{
		overlayDir: func() string { return deps.overlayDir },
		repoRoot:   func() (string, error) { return deps.repoRoot, nil },
		cache:      func() *pmgsandbox.ViolationCache { return deps.cache },
		locked:     func() bool { return true },
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"exec=/usr/bin/sh"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "global_lockdown")

	overlay, _, err := pmgsandbox.LoadOverlayForRepo(deps.overlayDir, deps.repoRoot)
	require.NoError(t, err)
	assert.Nil(t, overlay)
}

func TestAllow_LastNormalizesRelativeTargets(t *testing.T) {
	deps := newAllowDeps(t)
	cwd, err := os.Getwd()
	require.NoError(t, err)
	relTarget := "./.astro"
	wantAbs := filepath.Join(cwd, ".astro")

	report := &pmgsandbox.ViolationReport{
		SandboxName: pmgsandbox.DriverSeatbelt,
		Violations: []pmgsandbox.Violation{
			{Kind: pmgsandbox.ViolationKindFSWrite, Target: relTarget},
		},
	}
	_, err = deps.cache.Write(report)
	require.NoError(t, err)

	_, _, err = runAllowCmd(t, deps, "--last")
	require.NoError(t, err)

	overlay, _, err := pmgsandbox.LoadOverlayForRepo(deps.overlayDir, deps.repoRoot)
	require.NoError(t, err)
	require.NotNil(t, overlay)
	require.Len(t, overlay.Allow, 1)
	assert.Equal(t, wantAbs, overlay.Allow[0].Value, "cache-derived target should be normalized to absolute")
}
