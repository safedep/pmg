//go:build linux

package platform

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These end-to-end tests build the pmg binary and invoke the hidden
// `__landlock_sandbox_exec` entry point directly with a crafted policy file,
// bypassing the rest of pmg (config, proxy, etc.). They verify the helper
// flow on a real kernel + Landlock ABI.
//
// Opt-in: skipped unless PMG_LANDLOCK_E2E=1 is set in the environment. They
// require a kernel that allows installing seccomp without NNP from inside an
// unprivileged user namespace — Ubuntu 24.04 blocks this by default via
// `kernel.apparmor_restrict_unprivileged_userns=1`, so CI must disable
// AppArmor (or the sysctl) before setting the env var. Also skipped when
// kernel Landlock is unavailable or the pmg binary cannot be located/built.

const landlockRuleReadExec = uint64(13) // READ_FILE | READ_DIR | EXECUTE
const landlockRuleReadDir = uint64(12)  // READ_FILE | READ_DIR

// landlockE2EEnabled reports whether the user has opted into running these
// e2e tests. Default: skip. The CI landlock job sets PMG_LANDLOCK_E2E=1 after
// disabling AppArmor.
func landlockE2EEnabled() bool {
	v := os.Getenv("PMG_LANDLOCK_E2E")
	return v == "1" || v == "true" || v == "yes"
}

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
// returns (stdout, stderr, exit-code). The audit socket points nowhere; use
// runHelperWithAuditSocket to collect audit events.
func runHelper(t *testing.T, policyPath string) (string, string, int) {
	t.Helper()
	return runHelperWithAuditSocket(t, policyPath, "/tmp/pmg-test-audit.sock.nonexistent")
}

func runHelperWithAuditSocket(t *testing.T, policyPath, auditSocket string) (string, string, int) {
	t.Helper()
	pmg := buildPmgBinary(t)
	cmd := exec.Command(pmg,
		"__landlock_sandbox_exec",
		"--policy-file", policyPath,
		"--audit-socket", auditSocket,
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
	if !landlockE2EEnabled() {
		t.Skip("PMG_LANDLOCK_E2E not set; skipping landlock e2e (requires AppArmor disabled / unprivileged-userns sysctl)")
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
	if !landlockE2EEnabled() {
		t.Skip("PMG_LANDLOCK_E2E not set; skipping landlock e2e (requires AppArmor disabled / unprivileged-userns sysctl)")
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
	if !landlockE2EEnabled() {
		t.Skip("PMG_LANDLOCK_E2E not set; skipping landlock e2e (requires AppArmor disabled / unprivileged-userns sysctl)")
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

// TestLandlockHelper_GrandchildDenyBlocksRead is the big one: deny-rule
// enforcement must reach DESCENDANT processes, not just the direct target.
// This is the contract gap we historically had vs bubblewrap. We use a
// nested bash chain so the `cat` that actually opens the secret is a
// grandchild of the helper (bash -> bash -> cat), forcing enforcement to
// route through per-descendant /proc/<pid>/mem reads. Works because the
// shim installs seccomp inside a user namespace WITHOUT NO_NEW_PRIVS,
// keeping dumpable=1 through every execve in the tree.
func TestLandlockHelper_GrandchildDenyBlocksRead(t *testing.T) {
	if !landlockE2EEnabled() {
		t.Skip("PMG_LANDLOCK_E2E not set; skipping landlock e2e (requires AppArmor disabled / unprivileged-userns sysctl)")
	}
	if _, err := landlockDetectABI(); err != nil {
		t.Skipf("Landlock not available: %v", err)
	}
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash not found")
	}
	// Requires unprivileged user namespaces for the shim architecture.
	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		if len(b) > 0 && b[0] == '0' {
			t.Skip("unprivileged user namespaces disabled")
		}
	}

	home := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(home, ".ssh"), 0o700))
	secretPath := filepath.Join(home, ".ssh", "id_ed25519")
	const secret = "GRANDCHILD-SECRET-CONTENT"
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
		Command:          "/bin/bash",
		// Two layers of exec-via-bash before cat hits the secret.
		Args: []string{"-c",
			"exec /bin/bash -c 'exec /bin/cat " + secretPath + "'"},
	}
	policyPath := writePolicyFile(t, policy)

	stdout, stderr, _ := runHelper(t, policyPath)
	assert.NotContains(t, stdout, secret, "grandchild must not read the secret")
	combined := stdout + stderr
	assert.True(t,
		bytesContainsAny(combined, []string{"Permission denied", "EACCES"}),
		"expected permission-denied from grandchild; got: %q", combined)
}

// TestLandlockHelper_DenyEmitsAuditViolation closes the loop from a real
// in-kernel denial to the violation report surfaced by `pmg sandbox
// violations` / `explain`: the helper's supervisor denies a read, emits the
// audit event over the socket, and the driver's capture + mapping code must
// turn it into a typed fs_read violation.
func TestLandlockHelper_DenyEmitsAuditViolation(t *testing.T) {
	if !landlockE2EEnabled() {
		t.Skip("PMG_LANDLOCK_E2E not set; skipping landlock e2e (requires AppArmor disabled / unprivileged-userns sysctl)")
	}
	if _, err := landlockDetectABI(); err != nil {
		t.Skipf("Landlock not available: %v", err)
	}
	if _, err := os.Stat("/usr/bin/cat"); err != nil {
		t.Skip("/usr/bin/cat not found")
	}

	home := t.TempDir()
	secretPath := filepath.Join(home, ".ssh", "id_ed25519")
	require.NoError(t, os.Mkdir(filepath.Join(home, ".ssh"), 0o700))
	require.NoError(t, os.WriteFile(secretPath, []byte("SECRET"), 0o600))

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

	socketPath := filepath.Join(t.TempDir(), "audit.sock")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, listener.Close())
	}()

	s := &landlockSandbox{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		s.captureAuditEvents(conn)
		_ = conn.Close()
	}()

	stdout, stderr, exit := runHelperWithAuditSocket(t, policyPath, socketPath)
	assert.NotEqual(t, 0, exit, "cat should have failed; stdout=%q stderr=%q", stdout, stderr)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("audit reader did not finish after helper exit")
	}

	violations := extractLandlockViolations(s.auditEvents)
	require.NotEmpty(t, violations, "expected a captured violation; stdout=%q stderr=%q", stdout, stderr)

	v := violations[0]
	assert.Equal(t, sandbox.ViolationKindFSRead, v.Kind)
	assert.Equal(t, secretPath, v.Target)
	assert.Equal(t, filepath.Join(home, ".ssh"), v.RuleTarget)
	assert.Equal(t, "read access denied: "+secretPath, v.RuleLabel)
	assert.Equal(t, "cat", v.Process)
	assert.NotContains(t, v.RawLog, `"ts":0`)
}

// TestLandlockHelper_NetworkLockdownAllowsProxyPort is the positive control
// for network_via_proxy_only: a loopback connect to the configured proxy
// port must succeed while lockdown enforcement is active.
func TestLandlockHelper_NetworkLockdownAllowsProxyPort(t *testing.T) {
	if !landlockE2EEnabled() {
		t.Skip("PMG_LANDLOCK_E2E not set; skipping landlock e2e (requires AppArmor disabled / unprivileged-userns sysctl)")
	}
	if _, err := landlockDetectABI(); err != nil {
		t.Skipf("Landlock not available: %v", err)
	}
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash not found")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, listener.Close())
	}()
	proxyPort := uint16(listener.Addr().(*net.TCPAddr).Port)

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()

	policy := &landlockExecPolicy{
		FilesystemRules:  baseRules(),
		Network:          landlockNetworkPolicy{Lockdown: true, ProxyPort: proxyPort},
		SkipPIDNamespace: true,
		SkipIPCNamespace: true,
		Command:          "/bin/bash",
		Args:             []string{"-c", "exec 3<>/dev/tcp/127.0.0.1/" + strconv.Itoa(int(proxyPort))},
	}
	policyPath := writePolicyFile(t, policy)

	stdout, stderr, exit := runHelper(t, policyPath)
	assert.Equal(t, 0, exit, "loopback proxy connect must succeed; stdout=%q stderr=%q", stdout, stderr)

	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Error("listener never saw the sandboxed connect")
	}
}

// TestLandlockHelper_NetworkLockdownDeniesNonLoopback is the security-critical
// assertion: under lockdown a connect to a non-loopback address must be
// denied by the supervisor before any packet leaves — the address is in
// TEST-NET-3, so a failure of the sandbox (not of routing) is the only way
// to fail; and the audit pipeline must surface the denial as a typed
// network_connect violation.
func TestLandlockHelper_NetworkLockdownDeniesNonLoopback(t *testing.T) {
	if !landlockE2EEnabled() {
		t.Skip("PMG_LANDLOCK_E2E not set; skipping landlock e2e (requires AppArmor disabled / unprivileged-userns sysctl)")
	}
	if _, err := landlockDetectABI(); err != nil {
		t.Skipf("Landlock not available: %v", err)
	}
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash not found")
	}

	policy := &landlockExecPolicy{
		FilesystemRules:  baseRules(),
		Network:          landlockNetworkPolicy{Lockdown: true, ProxyPort: 54321},
		SkipPIDNamespace: true,
		SkipIPCNamespace: true,
		Command:          "/bin/bash",
		Args:             []string{"-c", "echo exfil >&2; exec 3<>/dev/tcp/203.0.113.9/443"},
	}
	policyPath := writePolicyFile(t, policy)

	socketPath := filepath.Join(t.TempDir(), "audit.sock")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, listener.Close())
	}()

	s := &landlockSandbox{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		s.captureAuditEvents(conn)
		_ = conn.Close()
	}()

	stdout, stderr, exit := runHelperWithAuditSocket(t, policyPath, socketPath)
	assert.NotEqual(t, 0, exit, "non-loopback connect must fail under lockdown; stdout=%q", stdout)
	assert.Contains(t, stdout+stderr, "exfil")

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("audit reader did not finish after helper exit")
	}

	violations := extractLandlockViolations(s.auditEvents)
	require.Len(t, violations, 1, "expected exactly one network violation; events=%v", s.auditEvents)
	v := violations[0]
	assert.Equal(t, sandbox.ViolationKindNetworkConnect, v.Kind)
	assert.Equal(t, "203.0.113.9:443", v.Target)
	assert.Equal(t, "bash", v.Process)
	assert.Contains(t, v.RuleLabel, "network_via_proxy_only")
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

// TestLandlockHelper_DenyOverlappingAllowRuleDoesNotWedgeShim guards the shim
// ordering: populating the Landlock ruleset opens every rule path, so a rule
// path that is also deny-listed must not abort the shim with EACCES before
// exec. The translator normally subtracts such rules (see
// landlockMaskDeniedRules); this feeds a crafted overlapping policy
// directly to the helper to pin the defense-in-depth property.
func TestLandlockHelper_DenyOverlappingAllowRuleDoesNotWedgeShim(t *testing.T) {
	if !landlockE2EEnabled() {
		t.Skip("PMG_LANDLOCK_E2E not set; skipping landlock e2e (requires AppArmor disabled / unprivileged-userns sysctl)")
	}
	if _, err := landlockDetectABI(); err != nil {
		t.Skipf("Landlock not available: %v", err)
	}

	home := t.TempDir()
	denyDir := filepath.Join(home, "hooks")
	require.NoError(t, os.Mkdir(denyDir, 0o755))

	policy := &landlockExecPolicy{
		FilesystemRules: append(baseRules(),
			landlockPathRule{Path: denyDir, Access: landlockRuleReadExec},
		),
		DenyPaths: []denyPathEntry{
			{Path: denyDir, Mode: denyBoth},
		},
		SkipPIDNamespace: true,
		SkipIPCNamespace: true,
		Command:          "/bin/echo",
		Args:             []string{"shim-survived"},
	}
	policyPath := writePolicyFile(t, policy)

	stdout, stderr, exit := runHelper(t, policyPath)
	assert.Equal(t, 0, exit, "shim must survive a deny/allow overlap: stderr=%s", stderr)
	assert.Contains(t, stdout, "shim-survived")
}

// TestLandlockHelper_DenyBlocksMoveLinkAndSymlink covers the routes around
// an openat-only deny under a broad Landlock write grant: rename the
// protected file to a new name, hard-link it, or read it through a symlink.
// The Landlock rule on $home grants every write right, so the supervisor
// is the only layer that can refuse.
func TestLandlockHelper_DenyBlocksMoveLinkAndSymlink(t *testing.T) {
	if !landlockE2EEnabled() {
		t.Skip("PMG_LANDLOCK_E2E not set; skipping landlock e2e (requires AppArmor disabled / unprivileged-userns sysctl)")
	}
	if _, err := landlockDetectABI(); err != nil {
		t.Skipf("Landlock not available: %v", err)
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not found")
	}

	home := t.TempDir()
	home, err := filepath.EvalSymlinks(home)
	require.NoError(t, err)
	secretDir := filepath.Join(home, "secrets")
	require.NoError(t, os.Mkdir(secretDir, 0o700))
	secretPath := filepath.Join(secretDir, "token")
	const secret = "MOVE-LINK-SECRET"
	require.NoError(t, os.WriteFile(secretPath, []byte(secret), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "git", "hooks"), 0o755))

	script := strings.Join([]string{
		"mv " + secretDir + " " + home + "/moved || echo MOVE_DENIED",
		"ln " + secretPath + " " + home + "/hardlink || echo LINK_DENIED",
		"ln -s " + secretPath + " " + home + "/symlink",
		"cat " + home + "/symlink || echo SYMLINK_READ_DENIED",
		"mv " + home + "/git " + home + "/gitx || echo ANCESTOR_MOVE_DENIED",
		"rm " + secretPath + " || echo UNLINK_DENIED",
		"echo evil > " + home + "/evil && mv " + home + "/evil " + home + "/git/hooks/pre-commit || echo MOVE_INTO_DENIED",
		"mv " + home + "/symlink " + home + "/symlink2 && echo UNRELATED_MOVE_OK",
	}, "\n")

	policy := &landlockExecPolicy{
		FilesystemRules: append(baseRules(),
			landlockPathRule{Path: home, Access: landlockReadAccess | landlockWriteAccessFull},
		),
		DenyPaths: []denyPathEntry{
			{Path: secretDir, Mode: denyBoth},
			{Path: filepath.Join(home, "git", "hooks"), Mode: denyBoth},
		},
		SkipPIDNamespace: true,
		SkipIPCNamespace: true,
		Command:          "/bin/sh",
		Args:             []string{"-c", script},
	}
	policyPath := writePolicyFile(t, policy)

	stdout, stderr, _ := runHelper(t, policyPath)
	combined := stdout + stderr

	for _, marker := range []string{
		"MOVE_DENIED", "LINK_DENIED", "SYMLINK_READ_DENIED", "ANCESTOR_MOVE_DENIED",
		"UNLINK_DENIED", "MOVE_INTO_DENIED", "UNRELATED_MOVE_OK",
	} {
		assert.Contains(t, stdout, marker, "stdout=%q stderr=%q", stdout, stderr)
	}
	assert.NotContains(t, combined, secret, "the secret must not leak through a link")

	_, err = os.Stat(secretPath)
	assert.NoError(t, err, "the protected file must stay in place")
	_, err = os.Stat(filepath.Join(home, "hardlink"))
	assert.True(t, os.IsNotExist(err), "no hard link to the protected file")
	_, err = os.Stat(filepath.Join(home, "git", "hooks", "pre-commit"))
	assert.True(t, os.IsNotExist(err), "nothing moved into the protected directory")
}
