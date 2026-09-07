//go:build linux

package platform

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests run real commands under a real bwrap sandbox and assert that the
// resulting denial reaches a violation report. They skip when bwrap is absent
// rather than being opted into by env var, since bwrap is the only requirement.

// requireBubblewrap skips unless bwrap is present and can actually spawn a
// sandbox: a host that disables unprivileged user namespaces has bwrap on PATH
// while every spawn fails, which would fail these tests instead of skipping.
//
// The probe succeeds rather than denies, because a denial and a failure to
// start both exit non-zero.
func requireBubblewrap(t *testing.T) *bubblewrapSandbox {
	t.Helper()

	b, err := newBubblewrapSandbox()
	require.NoError(t, err)

	if !b.IsAvailable() {
		t.Skip("bwrap not found on PATH")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	probe := exec.CommandContext(ctx, "bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--", "/bin/true")
	if out, err := probe.CombinedOutput(); err != nil {
		t.Skipf("bwrap cannot spawn a sandbox on this host: %v: %s", err, out)
	}

	return b
}

// bubblewrapE2EWorkdir returns a project directory under the sandbox tmpdir,
// which the translator binds read-write. A deny rule under it must still win,
// so every test here also proves the tmpdir bind is ordered before the denies.
func bubblewrapE2EWorkdir(t *testing.T) string {
	t.Helper()

	return t.TempDir()
}

func bubblewrapE2EPolicy(t *testing.T, workdir string) *sandbox.SandboxPolicy {
	t.Helper()

	return &sandbox.SandboxPolicy{
		Name:            "bubblewrap-e2e",
		PackageManagers: []string{"npm"},
		Filesystem: sandbox.FilesystemPolicy{
			AllowRead:  []string{"/usr", "/bin", "/lib", "/lib64", workdir},
			AllowWrite: []string{workdir},
		},
		Process: sandbox.ProcessPolicy{
			AllowExec: []string{"/usr/bin", "/bin"},
		},
	}
}

type sandboxRun struct {
	result *sandbox.ExecutionResult
	err    error
	stdout string
	stderr string
}

func runSandboxed(t *testing.T, b *bubblewrapSandbox, policy *sandbox.SandboxPolicy, argv ...string) sandboxRun {
	t.Helper()

	var stdout, stderr bytes.Buffer

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	result, err := b.Execute(context.Background(), cmd, policy, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, result.Close())
	})
	require.True(t, result.ShouldRun())

	return sandboxRun{
		result: result,
		err:    cmd.Run(),
		stdout: stdout.String(),
		stderr: stderr.String(),
	}
}

func (r sandboxRun) report(t *testing.T) *sandbox.ViolationReport {
	t.Helper()

	report, err := r.result.BestEffortViolation(r.err)
	require.NoError(t, err)

	return report
}

// A credential read is the case the sandbox exists for, so it is asserted end to
// end: the secret must not reach the process, and the user must be told why.
func TestBubblewrapE2EReportsDeniedCredentialRead(t *testing.T) {
	b := requireBubblewrap(t)

	workdir := bubblewrapE2EWorkdir(t)
	secret := filepath.Join(workdir, ".env")
	require.NoError(t, os.WriteFile(secret, []byte("TOKEN=secret\n"), 0o600))

	policy := bubblewrapE2EPolicy(t, workdir)
	policy.Filesystem.DenyRead = []string{secret}

	run := runSandboxed(t, b, policy, "/bin/cat", secret)
	require.Error(t, run.err)
	assert.NotContains(t, run.stdout, "TOKEN=secret", "the secret must not reach the process")

	report := run.report(t)
	require.NotNil(t, report, "stderr: %s", run.stderr)
	assert.Equal(t, sandbox.DriverBubblewrap, report.SandboxName)
	assert.Equal(t, "bubblewrap-e2e", report.PolicyName)

	explanation := sandbox.BuildExplanation(report)
	require.NotNil(t, explanation.Primary)
	assert.Equal(t, secret, explanation.Primary.Target)
	assert.Equal(t, sandbox.ViolationKindFSRead, explanation.Primary.Kind)
	assert.Equal(t, "cat", explanation.Primary.Process)

	assert.True(t, report.OutputDerived)
	assert.Nil(t, explanation.Override, "output-derived evidence is not offered as an allowance")
}

func TestBubblewrapE2EReportsDeniedWrite(t *testing.T) {
	b := requireBubblewrap(t)

	workdir := bubblewrapE2EWorkdir(t)
	protected := filepath.Join(workdir, "locked.txt")
	require.NoError(t, os.WriteFile(protected, []byte("original\n"), 0o600))

	policy := bubblewrapE2EPolicy(t, workdir)
	policy.Filesystem.DenyWrite = []string{protected}

	run := runSandboxed(t, b, policy, "/bin/sh", "-c", "echo tampered > "+protected)
	require.Error(t, run.err)

	report := run.report(t)
	require.NotNil(t, report, "stderr: %s", run.stderr)

	explanation := sandbox.BuildExplanation(report)
	require.NotNil(t, explanation.Primary)
	assert.Equal(t, protected, explanation.Primary.Target)
	assert.Equal(t, sandbox.ViolationKindFSWrite, explanation.Primary.Kind)

	contents, err := os.ReadFile(protected)
	require.NoError(t, err)
	assert.Equal(t, "original\n", string(contents), "the write must not have landed")
}

func TestBubblewrapE2EReportsReadOnlyWrite(t *testing.T) {
	b := requireBubblewrap(t)

	workdir := bubblewrapE2EWorkdir(t)

	run := runSandboxed(t, b, bubblewrapE2EPolicy(t, workdir),
		"/bin/sh", "-c", "echo denied > /usr/pmg-e2e-should-not-exist")
	require.Error(t, run.err)

	report := run.report(t)
	require.NotNil(t, report, "stderr: %s", run.stderr)

	explanation := sandbox.BuildExplanation(report)
	require.NotNil(t, explanation.Primary)
	assert.Equal(t, "/usr/pmg-e2e-should-not-exist", explanation.Primary.Target)
	assert.Equal(t, sandbox.ViolationKindFSWrite, explanation.Primary.Kind)
}

func TestBubblewrapE2ESuccessfulRunReportsNothing(t *testing.T) {
	b := requireBubblewrap(t)

	workdir := bubblewrapE2EWorkdir(t)
	readable := filepath.Join(workdir, "ok.txt")
	require.NoError(t, os.WriteFile(readable, []byte("fine\n"), 0o600))

	run := runSandboxed(t, b, bubblewrapE2EPolicy(t, workdir), "/bin/cat", readable)
	require.NoError(t, run.err, "stderr: %s", run.stderr)

	assert.Nil(t, run.report(t))
}
