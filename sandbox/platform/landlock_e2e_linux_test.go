//go:build linux

package platform

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These end-to-end tests build the pmg binary and invoke the hidden
// `__landlock_sandbox_exec` entry point directly with a crafted policy file,
// bypassing the rest of pmg (config, proxy, etc.). They verify the helper
// flow on a real kernel + Landlock ABI.
//
// Skipped when kernel Landlock is unavailable or the pmg binary cannot be
// located/built. Set LANDLOCK_E2E=skip to skip unconditionally.

const landlockRuleReadExec = uint64(13) // READ_FILE | READ_DIR | EXECUTE
const landlockRuleReadDir = uint64(12)  // READ_FILE | READ_DIR

// buildPmgBinary locates or builds bin/pmg. Returns absolute path.
func buildPmgBinary(t *testing.T) string {
	t.Helper()
	// Walk upward from CWD to find the repo root (contains go.mod + main.go).
	cwd, err := os.Getwd()
	require.NoError(t, err)
	dir := cwd
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "main.go")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("could not locate pmg repo root")
		}
		dir = parent
	}
	binPath := filepath.Join(dir, "bin", "pmg")
	if _, err := os.Stat(binPath); err == nil {
		return binPath
	}
	// Build fresh.
	cmd := exec.Command("go", "build", "-o", binPath, "main.go")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "build failed: %s", out)
	return binPath
}

// writePolicyFile serializes a minimal landlockExecPolicy to a temp file.
func writePolicyFile(t *testing.T, p *landlockExecPolicy) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "policy-*.json")
	require.NoError(t, err)
	require.NoError(t, json.NewEncoder(f).Encode(p))
	require.NoError(t, f.Close())
	return f.Name()
}

// runHelper invokes the hidden helper subcommand with the given policy and
// returns (stdout, stderr, exit-code).
func runHelper(t *testing.T, policyPath string) (string, string, int) {
	t.Helper()
	pmg := buildPmgBinary(t)
	cmd := exec.Command(pmg,
		"__landlock_sandbox_exec",
		"--policy-file", policyPath,
		"--audit-socket", "/tmp/pmg-test-audit.sock.nonexistent",
	)
	// PMG_KEEP_POLICY ensures test state is visible on failure.
	cmd.Env = append(os.Environ(), "PMG_KEEP_POLICY=1")
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	exit := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			exit = -1
		}
	}
	return outBuf.String(), errBuf.String(), exit
}

// baseRules returns a minimal allow-list sufficient to run common binaries.
func baseRules() []landlockPathRule {
	return []landlockPathRule{
		{Path: "/", Access: landlockRuleReadExec},
		{Path: "/usr", Access: landlockRuleReadExec},
		{Path: "/bin", Access: landlockRuleReadExec},
		{Path: "/lib", Access: landlockRuleReadExec},
		{Path: "/lib64", Access: landlockRuleReadExec},
		{Path: "/usr/lib", Access: landlockRuleReadExec},
		{Path: "/usr/lib64", Access: landlockRuleReadExec},
		{Path: "/proc", Access: landlockRuleReadDir},
		{Path: "/dev/null", Access: landlockRuleReadDir},
		{Path: "/dev/urandom", Access: landlockRuleReadDir},
	}
}

// TestLandlockHelper_EchoRuns is the simplest smoke test: the helper should
// be able to install its filter, fork /bin/echo, collect its output, and
// exit cleanly. Regression for the supervisor.Stop hang and for the
// landlock-before-seccomp ordering deadlock.
func TestLandlockHelper_EchoRuns(t *testing.T) {
	if os.Getenv("LANDLOCK_E2E") == "skip" {
		t.Skip("LANDLOCK_E2E=skip")
	}
	if _, err := landlockDetectABI(); err != nil {
		t.Skipf("Landlock not available: %v", err)
	}

	policy := &landlockExecPolicy{
		FilesystemRules:  baseRules(),
		SkipPIDNamespace: true,
		SkipIPCNamespace: true,
		Command:          "/bin/echo",
		Args:             []string{"sandbox-ok"},
	}
	policyPath := writePolicyFile(t, policy)

	stdout, stderr, exit := runHelper(t, policyPath)
	assert.Equal(t, 0, exit, "helper exited non-zero: stderr=%s", stderr)
	assert.Contains(t, stdout, "sandbox-ok")
}

// TestLandlockHelper_DirectChildDenyBlocksRead is the security-critical
// assertion: when the policy says "allow /" but "deny ~/.ssh", a direct
// target that tries to read ~/.ssh must see EACCES. This works because the
// target is the helper's direct child, so /proc/<pid>/mem is readable and
// seccomp-notify can resolve the openat path argument.
//
// Grandchild processes (e.g. node spawned by an npm shell wrapper) hit a
// dumpable=0 limitation and are covered by a separate TODO — see
// docs/sandbox.md for details. This test intentionally uses /usr/bin/cat
// as a direct target to keep enforcement in scope.
func TestLandlockHelper_DirectChildDenyBlocksRead(t *testing.T) {
	if os.Getenv("LANDLOCK_E2E") == "skip" {
		t.Skip("LANDLOCK_E2E=skip")
	}
	if _, err := landlockDetectABI(); err != nil {
		t.Skipf("Landlock not available: %v", err)
	}
	if _, err := os.Stat("/usr/bin/cat"); err != nil {
		t.Skip("/usr/bin/cat not found")
	}

	// Build a fake HOME with a decoy secret so we don't need real ~/.ssh.
	home := t.TempDir()
	secretPath := filepath.Join(home, ".ssh", "id_ed25519")
	require.NoError(t, os.Mkdir(filepath.Join(home, ".ssh"), 0o700))
	const secret = "SECRET-PRIVATE-KEY-CONTENT"
	require.NoError(t, os.WriteFile(secretPath, []byte(secret), 0o600))

	policy := &landlockExecPolicy{
		FilesystemRules: append(baseRules(),
			landlockPathRule{Path: home, Access: landlockRuleReadExec},
		),
		DenyPaths: []denyPathEntry{
			{Path: filepath.Join(home, ".ssh"), Mode: denyBoth},
		},
		SkipPIDNamespace: true,
		SkipIPCNamespace: true,
		Command:          "/usr/bin/cat",
		Args:             []string{secretPath},
	}
	policyPath := writePolicyFile(t, policy)

	stdout, stderr, exit := runHelper(t, policyPath)
	assert.NotEqual(t, 0, exit, "cat should have failed; stdout=%q", stdout)
	assert.NotContains(t, stdout, secret, "secret content must not leak")
	combined := stdout + stderr
	assert.True(t,
		bytesContainsAny(combined, []string{"Permission denied", "EACCES"}),
		"expected a permission-denied error; got: %q", combined)
}

// TestLandlockHelper_DenyBothBlocksWrite extends the direct-child test to
// verify that denyBoth blocks write access as well. Uses /usr/bin/tee as
// the *direct* target (no shell wrapper) so seccomp-notify can actually
// read the openat path argument — see grandchild limitation note in
// TestLandlockHelper_DirectChildDenyBlocksRead.
func TestLandlockHelper_DenyBothBlocksWrite(t *testing.T) {
	if os.Getenv("LANDLOCK_E2E") == "skip" {
		t.Skip("LANDLOCK_E2E=skip")
	}
	if _, err := landlockDetectABI(); err != nil {
		t.Skipf("Landlock not available: %v", err)
	}
	if _, err := os.Stat("/usr/bin/tee"); err != nil {
		t.Skip("/usr/bin/tee not found")
	}

	home := t.TempDir()
	denyDir := filepath.Join(home, "secrets")
	require.NoError(t, os.Mkdir(denyDir, 0o700))
	writeTarget := filepath.Join(denyDir, "token")

	// AccessFSWriteFile (0x2) + MakeReg (0x100) so creation under $home is
	// permitted by Landlock; the seccomp deny is what should block.
	policy := &landlockExecPolicy{
		FilesystemRules: append(baseRules(),
			landlockPathRule{Path: home, Access: landlockRuleReadExec | 0x2 | 0x100},
		),
		DenyPaths: []denyPathEntry{
			{Path: denyDir, Mode: denyBoth},
		},
		SkipPIDNamespace: true,
		SkipIPCNamespace: true,
		Command:          "/usr/bin/tee",
		Args:             []string{writeTarget},
	}
	policyPath := writePolicyFile(t, policy)

	stdout, stderr, exit := runHelper(t, policyPath)
	combined := stdout + stderr
	if _, err := os.Stat(writeTarget); err == nil {
		t.Errorf("write target was created: %s (stdout=%q stderr=%q exit=%d)", writeTarget, stdout, stderr, exit)
	}
	assert.True(t,
		bytesContainsAny(combined, []string{"Permission denied", "EACCES"}),
		"expected permission denied; got: %q exit=%d", combined, exit)
}

// bytesContainsAny reports whether s contains any of the given substrings.
func bytesContainsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if bytes.Contains([]byte(s), []byte(sub)) {
			return true
		}
	}
	return false
}
