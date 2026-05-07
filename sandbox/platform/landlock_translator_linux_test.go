//go:build linux

package platform

import (
	"os"
	"strings"
	"testing"

	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox"
)

func newTestPolicy() *sandbox.SandboxPolicy {
	return &sandbox.SandboxPolicy{
		Name:            "test-policy",
		PackageManagers: []string{"npm"},
	}
}

func findRule(rules []landlockPathRule, path string) *landlockPathRule {
	for i := range rules {
		if rules[i].Path == path {
			return &rules[i]
		}
	}
	return nil
}

func findDenyPath(entries []denyPathEntry, path string) *denyPathEntry {
	for i := range entries {
		if entries[i].Path == path {
			return &entries[i]
		}
	}
	return nil
}

func TestLandlockTranslatePolicy_AllowRead(t *testing.T) {
	tests := []struct {
		name      string
		paths     []string
		wantPaths []string
	}{
		{
			name:      "single path",
			paths:     []string{"/usr/lib"},
			wantPaths: []string{"/usr/lib"},
		},
		{
			name:      "multiple paths",
			paths:     []string{"/usr/lib", "/etc"},
			wantPaths: []string{"/usr/lib", "/etc"},
		},
	}

	abi := newLandlockABI(3)
	expectedAccess := uint64(llsyscall.AccessFSReadFile | llsyscall.AccessFSReadDir | llsyscall.AccessFSExecute)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newTestPolicy()
			policy.Filesystem.AllowRead = tt.paths

			ep, err := landlockTranslatePolicy(policy, abi)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for _, wantPath := range tt.wantPaths {
				rule := findRule(ep.FilesystemRules, wantPath)
				if rule == nil {
					t.Errorf("expected rule for path %s, not found", wantPath)
					continue
				}
				if rule.Access != expectedAccess {
					t.Errorf("path %s: access = %x, want %x", wantPath, rule.Access, expectedAccess)
				}
			}
		})
	}
}

func TestLandlockTranslatePolicy_AllowWrite(t *testing.T) {
	tests := []struct {
		name       string
		abiVersion int
		wantRefer  bool
		wantTrunc  bool
	}{
		{
			name:       "V1 - no Refer, no Truncate",
			abiVersion: 1,
			wantRefer:  false,
			wantTrunc:  false,
		},
		{
			name:       "V2 - has Refer, no Truncate",
			abiVersion: 2,
			wantRefer:  true,
			wantTrunc:  false,
		},
		{
			name:       "V3 - has Refer and Truncate",
			abiVersion: 3,
			wantRefer:  true,
			wantTrunc:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			abi := newLandlockABI(tt.abiVersion)
			policy := newTestPolicy()
			policy.Filesystem.AllowWrite = []string{"/tmp/test"}

			ep, err := landlockTranslatePolicy(policy, abi)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			rule := findRule(ep.FilesystemRules, "/tmp/test")
			if rule == nil {
				t.Fatal("expected rule for /tmp/test, not found")
			}

			hasRefer := rule.Access&uint64(llsyscall.AccessFSRefer) != 0
			hasTrunc := rule.Access&uint64(llsyscall.AccessFSTruncate) != 0

			if hasRefer != tt.wantRefer {
				t.Errorf("Refer flag: got %v, want %v", hasRefer, tt.wantRefer)
			}
			if hasTrunc != tt.wantTrunc {
				t.Errorf("Truncate flag: got %v, want %v", hasTrunc, tt.wantTrunc)
			}

			// Verify base write flags are always present
			if rule.Access&uint64(llsyscall.AccessFSWriteFile) == 0 {
				t.Error("WriteFile flag should always be present")
			}
			if rule.Access&uint64(llsyscall.AccessFSMakeReg) == 0 {
				t.Error("MakeReg flag should always be present")
			}
		})
	}
}

func TestLandlockTranslatePolicy_AllowExec(t *testing.T) {
	policy := newTestPolicy()
	policy.Process.AllowExec = []string{"/usr/bin/node", "/usr/bin/npm"}
	abi := newLandlockABI(3)

	ep, err := landlockTranslatePolicy(policy, abi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Execute access includes ReadFile because the kernel must read the
	// shebang line of script files to determine the interpreter.
	expectedAccess := uint64(llsyscall.AccessFSExecute | llsyscall.AccessFSReadFile)

	for _, path := range []string{"/usr/bin/node", "/usr/bin/npm"} {
		rule := findRule(ep.FilesystemRules, path)
		if rule == nil {
			t.Errorf("expected rule for %s, not found", path)
			continue
		}
		if rule.Access != expectedAccess {
			t.Errorf("path %s: access = %x, want %x", path, rule.Access, expectedAccess)
		}
	}
}

func TestLandlockTranslatePolicy_DenyRead(t *testing.T) {
	policy := newTestPolicy()
	policy.Filesystem.DenyRead = []string{"/etc/shadow", "/etc/passwd"}
	abi := newLandlockABI(3)

	ep, err := landlockTranslatePolicy(policy, abi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, path := range []string{"/etc/shadow", "/etc/passwd"} {
		entry := findDenyPath(ep.DenyPaths, path)
		if entry == nil {
			t.Errorf("expected deny entry for %s, not found", path)
			continue
		}
		if entry.Mode != denyRead {
			t.Errorf("path %s: mode = %d, want denyRead (%d)", path, entry.Mode, denyRead)
		}
	}
}

func TestLandlockTranslatePolicy_DenyWrite(t *testing.T) {
	policy := newTestPolicy()
	// DenyWrite is only effective within writable areas. Add /etc as writable
	// so the deny rule for /etc/hosts is not pruned as redundant.
	policy.Filesystem.AllowWrite = []string{"/etc/**"}
	policy.Filesystem.DenyWrite = []string{"/etc/hosts"}
	abi := newLandlockABI(3)

	ep, err := landlockTranslatePolicy(policy, abi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entry := findDenyPath(ep.DenyPaths, "/etc/hosts")
	if entry == nil {
		t.Fatal("expected deny entry for /etc/hosts, not found")
	}
	if entry.Mode != denyWrite {
		t.Errorf("mode = %d, want denyWrite (%d)", entry.Mode, denyWrite)
	}
}

func TestLandlockTranslatePolicy_DenyWriteSkippedWhenNotWritable(t *testing.T) {
	policy := newTestPolicy()
	// No AllowWrite for /etc, so deny_write for /etc/hosts is redundant
	// (Landlock already prevents writes).
	policy.Filesystem.DenyWrite = []string{"/etc/hosts"}
	abi := newLandlockABI(3)

	ep, err := landlockTranslatePolicy(policy, abi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entry := findDenyPath(ep.DenyPaths, "/etc/hosts")
	if entry != nil {
		t.Error("expected deny entry for /etc/hosts to be pruned (not in writable area)")
	}
}

func TestLandlockTranslatePolicy_DenyExec(t *testing.T) {
	policy := newTestPolicy()
	policy.Process.DenyExec = []string{"/usr/bin/curl", "/usr/bin/wget"}
	abi := newLandlockABI(3)

	ep, err := landlockTranslatePolicy(policy, abi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, path := range []string{"/usr/bin/curl", "/usr/bin/wget"} {
		found := false
		for _, p := range ep.DenyExecPaths {
			if p == path {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s in DenyExecPaths, not found", path)
		}
	}
}

func TestLandlockTranslatePolicy_MandatoryDenies(t *testing.T) {
	policy := newTestPolicy()
	policy.Filesystem.AllowRead = []string{"/usr"}
	abi := newLandlockABI(3)

	ep, err := landlockTranslatePolicy(policy, abi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mandatory denies should always be present with denyBoth mode
	if len(ep.DenyPaths) == 0 {
		t.Fatal("expected mandatory deny paths, got none")
	}

	// Check that at least some mandatory denies have denyBoth mode
	hasDenyBoth := false
	for _, entry := range ep.DenyPaths {
		if entry.Mode == denyBoth {
			hasDenyBoth = true
			break
		}
	}
	if !hasDenyBoth {
		t.Error("expected at least one mandatory deny with denyBoth mode")
	}

	// Check that .env is in the mandatory denies (it should always be there)
	hasEnvDeny := false
	for _, entry := range ep.DenyPaths {
		if strings.HasSuffix(entry.Path, "/.env") && entry.Mode == denyBoth {
			hasEnvDeny = true
			break
		}
	}
	if !hasEnvDeny {
		t.Error("expected .env in mandatory deny paths with denyBoth mode")
	}
}

func TestLandlockTranslatePolicy_ImplicitRules(t *testing.T) {
	policy := newTestPolicy()
	policy.Filesystem.AllowRead = []string{"/usr"}
	abi := newLandlockABI(3)

	ep, err := landlockTranslatePolicy(policy, abi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	readAccess := uint64(llsyscall.AccessFSReadFile | llsyscall.AccessFSReadDir | llsyscall.AccessFSExecute)

	// /proc must be present with read access
	procRule := findRule(ep.FilesystemRules, "/proc")
	if procRule == nil {
		t.Error("expected implicit /proc rule")
	} else if procRule.Access != readAccess {
		t.Errorf("/proc access = %x, want read access %x", procRule.Access, readAccess)
	}

	// /dev/null, /dev/zero, /dev/random, /dev/urandom must be present with read+write
	for _, dev := range []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"} {
		rule := findRule(ep.FilesystemRules, dev)
		if rule == nil {
			t.Errorf("expected implicit rule for %s", dev)
			continue
		}
		// Should have both read and write access
		if rule.Access&readAccess != readAccess {
			t.Errorf("%s: missing read access flags", dev)
		}
		if rule.Access&uint64(llsyscall.AccessFSWriteFile) == 0 {
			t.Errorf("%s: missing write access flags", dev)
		}
	}

	// os.TempDir() must be present with write access
	tmpDir := os.TempDir()
	tmpRule := findRule(ep.FilesystemRules, tmpDir)
	if tmpRule == nil {
		t.Errorf("expected implicit rule for %s", tmpDir)
	} else if tmpRule.Access&uint64(llsyscall.AccessFSWriteFile) == 0 {
		t.Errorf("%s: missing write access flags", tmpDir)
	}
}

func TestLandlockTranslatePolicy_AllowPTY_True(t *testing.T) {
	policy := newTestPolicy()
	policy.AllowPTY = utils.PtrTo(true)
	policy.Filesystem.AllowRead = []string{"/usr"}
	abi := newLandlockABI(5) // V5 has IoctlDev

	ep, err := landlockTranslatePolicy(policy, abi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !ep.AllowPTY {
		t.Error("expected AllowPTY to be true")
	}

	// Check /dev/pts
	ptsRule := findRule(ep.FilesystemRules, "/dev/pts")
	if ptsRule == nil {
		t.Fatal("expected rule for /dev/pts")
	}
	if ptsRule.Access&uint64(llsyscall.AccessFSReadFile) == 0 {
		t.Error("/dev/pts: missing read access")
	}
	if ptsRule.Access&uint64(llsyscall.AccessFSWriteFile) == 0 {
		t.Error("/dev/pts: missing write access")
	}
	// V5+ should have IoctlDev
	if ptsRule.Access&uint64(llsyscall.AccessFSIoctlDev) == 0 {
		t.Error("/dev/pts: missing IoctlDev access on V5+")
	}

	// Check /dev/ptmx
	ptmxRule := findRule(ep.FilesystemRules, "/dev/ptmx")
	if ptmxRule == nil {
		t.Fatal("expected rule for /dev/ptmx")
	}
	if ptmxRule.Access&uint64(llsyscall.AccessFSIoctlDev) == 0 {
		t.Error("/dev/ptmx: missing IoctlDev access on V5+")
	}
}

func TestLandlockTranslatePolicy_AllowPTY_Nil(t *testing.T) {
	policy := newTestPolicy()
	policy.AllowPTY = nil // nil means false
	policy.Filesystem.AllowRead = []string{"/usr"}
	abi := newLandlockABI(3)

	ep, err := landlockTranslatePolicy(policy, abi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ep.AllowPTY {
		t.Error("expected AllowPTY to be false when nil")
	}

	// /dev/pts and /dev/ptmx should NOT be in rules
	if findRule(ep.FilesystemRules, "/dev/pts") != nil {
		t.Error("unexpected rule for /dev/pts when AllowPTY is nil")
	}
	if findRule(ep.FilesystemRules, "/dev/ptmx") != nil {
		t.Error("unexpected rule for /dev/ptmx when AllowPTY is nil")
	}
}

func TestLandlockTranslatePolicy_ProcExplicitAllow(t *testing.T) {
	policy := newTestPolicy()
	policy.Filesystem.AllowRead = []string{"/proc/cpuinfo"}
	abi := newLandlockABI(3)

	ep, err := landlockTranslatePolicy(policy, abi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !ep.SkipPIDNamespace {
		t.Error("expected SkipPIDNamespace=true when /proc/cpuinfo is allowed")
	}
}

func TestLandlockTranslatePolicy_ProcSelfOnly(t *testing.T) {
	policy := newTestPolicy()
	policy.Filesystem.AllowRead = []string{"/proc/self/status", "/proc/self/fd"}
	abi := newLandlockABI(3)

	ep, err := landlockTranslatePolicy(policy, abi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ep.SkipPIDNamespace {
		t.Error("expected SkipPIDNamespace=false when only /proc/self paths are allowed")
	}
}

func TestLandlockTranslatePolicy_ProcDenyDropped(t *testing.T) {
	policy := newTestPolicy()
	policy.Filesystem.DenyRead = []string{"/proc/kcore", "/etc/shadow"}
	abi := newLandlockABI(3)

	ep, err := landlockTranslatePolicy(policy, abi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// /proc/kcore should be dropped
	for _, entry := range ep.DenyPaths {
		if strings.HasPrefix(entry.Path, "/proc") {
			t.Errorf("expected /proc deny entries to be dropped, found: %s", entry.Path)
		}
	}

	// /etc/shadow should remain
	found := false
	for _, entry := range ep.DenyPaths {
		if entry.Path == "/etc/shadow" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected /etc/shadow deny entry to remain")
	}
}

func TestLandlockTranslatePolicy_AllowGitConfig_Nil(t *testing.T) {
	policy := newTestPolicy()
	policy.AllowGitConfig = nil // nil means false -> .git/config should be in mandatory denies
	policy.Filesystem.AllowRead = []string{"/usr"}
	abi := newLandlockABI(3)

	ep, err := landlockTranslatePolicy(policy, abi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// .git/config should be in deny paths
	hasGitConfigDeny := false
	for _, entry := range ep.DenyPaths {
		if strings.HasSuffix(entry.Path, ".git/config") {
			hasGitConfigDeny = true
			break
		}
	}
	if !hasGitConfigDeny {
		t.Error("expected .git/config in mandatory deny paths when AllowGitConfig is nil")
	}
}

func TestLandlockTranslatePolicy_AllowGitConfig_True(t *testing.T) {
	policy := newTestPolicy()
	policy.AllowGitConfig = utils.PtrTo(true)
	policy.Filesystem.AllowRead = []string{"/usr"}
	abi := newLandlockABI(3)

	ep, err := landlockTranslatePolicy(policy, abi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// .git/config should NOT be in deny paths
	for _, entry := range ep.DenyPaths {
		if strings.HasSuffix(entry.Path, ".git/config") {
			t.Error("expected .git/config to NOT be in mandatory deny paths when AllowGitConfig is true")
			break
		}
	}
}

func TestLandlockPolicyExplicitlyAllowsProc(t *testing.T) {
	tests := []struct {
		name      string
		readPaths []string
		writePaths []string
		want      bool
	}{
		{
			name:      "no proc paths",
			readPaths: []string{"/usr/lib", "/etc"},
			want:      false,
		},
		{
			name:      "/proc/self only",
			readPaths: []string{"/proc/self"},
			want:      false,
		},
		{
			name:      "/proc/self/status",
			readPaths: []string{"/proc/self/status"},
			want:      false,
		},
		{
			name:      "/proc/cpuinfo triggers",
			readPaths: []string{"/proc/cpuinfo"},
			want:      true,
		},
		{
			name:      "/proc/1/status triggers",
			readPaths: []string{"/proc/1/status"},
			want:      true,
		},
		{
			name:       "/proc in write paths triggers",
			writePaths: []string{"/proc/sys/kernel/randomize_va_space"},
			want:       true,
		},
		{
			name:      "/proc alone triggers",
			readPaths: []string{"/proc"},
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := newTestPolicy()
			policy.Filesystem.AllowRead = tt.readPaths
			policy.Filesystem.AllowWrite = tt.writePaths

			got := landlockPolicyExplicitlyAllowsProc(policy)
			if got != tt.want {
				t.Errorf("landlockPolicyExplicitlyAllowsProc() = %v, want %v", got, tt.want)
			}
		})
	}
}
