//go:build linux

package platform

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestSeccompStructSizes(t *testing.T) {
	tests := []struct {
		name     string
		got      uintptr
		expected uintptr
	}{
		{"seccompData", unsafe.Sizeof(seccompData{}), 64},
		{"seccompNotification", unsafe.Sizeof(seccompNotification{}), 80},
		{"seccompNotifResp", unsafe.Sizeof(seccompNotifResp{}), 24},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("sizeof(%s) = %d, want %d", tt.name, tt.got, tt.expected)
			}
		})
	}
}

// filterNrLoadIndex is the index of the instruction that loads the syscall
// number: it follows the arch check.
func filterNrLoadIndex() int {
	if seccompNativeArch != 0 {
		return 3
	}
	return 0
}

// filterPrefixLen is the number of instructions before the per-syscall
// comparisons: the arch check, the nr load and the x32 guard.
func filterPrefixLen() int {
	n := filterNrLoadIndex() + 1
	if seccompX32SyscallBit != 0 {
		n += 2
	}
	return n
}

func TestLandlockBuildNotifyFilter(t *testing.T) {
	tests := []struct {
		name     string
		syscalls []uint32
	}{
		{"no syscalls", nil},
		{"exec only", []uint32{uint32(unix.SYS_EXECVE), uint32(unix.SYS_EXECVEAT)}},
		{"exec + open", []uint32{uint32(unix.SYS_EXECVE), uint32(unix.SYS_EXECVEAT), uint32(unix.SYS_OPENAT), uint32(unix.SYS_OPENAT2)}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prog := landlockBuildNotifyFilter(tc.syscalls...)
			require.NotNil(t, prog)
			require.NotNil(t, prog.Filter)
			assert.Equal(t, uint16(filterPrefixLen()+len(tc.syscalls)+2), prog.Len)
		})
	}
}

func TestLandlockBuildNotifyFilter_ArchGuard(t *testing.T) {
	if seccompNativeArch == 0 {
		t.Skip("no native audit arch on this architecture")
	}
	prog := landlockBuildNotifyFilter(uint32(unix.SYS_EXECVE))
	instructions := unsafe.Slice(prog.Filter, prog.Len)

	assert.Equal(t, uint16(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS), instructions[0].Code)
	assert.Equal(t, uint32(seccompDataArchOffset), instructions[0].K)
	assert.Equal(t, uint16(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K), instructions[1].Code)
	assert.Equal(t, uint32(seccompNativeArch), instructions[1].K)
	assert.Equal(t, uint8(1), instructions[1].Jt, "native arch skips the kill")
	assert.Equal(t, uint16(unix.BPF_RET|unix.BPF_K), instructions[2].Code)
	assert.Equal(t, uint32(unix.SECCOMP_RET_KILL_PROCESS), instructions[2].K)
	assert.Equal(t, uint32(seccompDataNrOffset), instructions[3].K)

	if seccompX32SyscallBit != 0 {
		assert.Equal(t, uint16(unix.BPF_JMP|unix.BPF_JGE|unix.BPF_K), instructions[4].Code)
		assert.Equal(t, uint32(seccompX32SyscallBit), instructions[4].K)
		assert.Equal(t, uint8(1), instructions[4].Jf, "a native number skips the kill")
		assert.Equal(t, uint32(unix.SECCOMP_RET_KILL_PROCESS), instructions[5].K)
	}
}

func TestLandlockBuildNotifyFilter_InstructionTypes(t *testing.T) {
	syscalls := []uint32{uint32(unix.SYS_EXECVE), uint32(unix.SYS_EXECVEAT), uint32(unix.SYS_CONNECT)}
	prog := landlockBuildNotifyFilter(syscalls...)

	instructions := unsafe.Slice(prog.Filter, prog.Len)
	prefix := filterPrefixLen()

	load := instructions[filterNrLoadIndex()]
	assert.Equal(t, uint16(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS), load.Code)
	assert.Equal(t, uint32(seccompDataNrOffset), load.K)

	// Each comparison jumps to the final notify instruction on match.
	for i, sc := range syscalls {
		cmp := instructions[prefix+i]
		assert.Equal(t, uint16(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K), cmp.Code, "instruction %d", prefix+i)
		assert.Equal(t, sc, cmp.K, "instruction %d", prefix+i)
		assert.Equal(t, uint8(len(syscalls)-i), cmp.Jt, "instruction %d must land on RET USER_NOTIF", prefix+i)
		assert.Equal(t, uint8(0), cmp.Jf, "instruction %d falls through on mismatch", prefix+i)
	}

	// Second-to-last allows, last notifies.
	secondToLast := instructions[prog.Len-2]
	assert.Equal(t, uint16(unix.BPF_RET|unix.BPF_K), secondToLast.Code)
	assert.Equal(t, uint32(unix.SECCOMP_RET_ALLOW), secondToLast.K)

	last := instructions[prog.Len-1]
	assert.Equal(t, uint16(unix.BPF_RET|unix.BPF_K), last.Code)
	assert.Equal(t, uint32(unix.SECCOMP_RET_USER_NOTIF), last.K)
}

func TestLandlockNotifySyscalls(t *testing.T) {
	execOnly := []uint32{uint32(unix.SYS_EXECVE), uint32(unix.SYS_EXECVEAT)}

	tests := []struct {
		name           string
		network        landlockNetworkPolicy
		interceptPaths bool
		want           []uint32
	}{
		{"exec always", landlockNetworkPolicy{}, false, execOnly},
		{"path syscalls when deny paths exist", landlockNetworkPolicy{}, true, append(append([]uint32{}, execOnly...), pathSyscallNumbers()...)},
		{"network under lockdown", landlockNetworkPolicy{Lockdown: true}, false, append(append([]uint32{}, execOnly...), uint32(unix.SYS_CONNECT), uint32(unix.SYS_SENDTO), uint32(unix.SYS_SENDMSG), uint32(unix.SYS_IO_URING_SETUP))},
		{"no network without lockdown", landlockNetworkPolicy{ProxyPort: 8080}, false, execOnly},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, landlockNotifySyscalls(tc.network, tc.interceptPaths))
		})
	}
}

// Every syscall that can move, link, remove or create a path must be
// trapped, or a broad Landlock write grant lets a process route around the
// deny list. The names are unique because the diagnostics map them back.
func TestSeccompPathSyscalls_Coverage(t *testing.T) {
	trapped := landlockNotifySyscalls(landlockNetworkPolicy{}, true)
	for _, nr := range []uint32{
		unix.SYS_OPENAT, unix.SYS_OPENAT2, unix.SYS_RENAMEAT2, unix.SYS_LINKAT,
		unix.SYS_UNLINKAT, unix.SYS_MKDIRAT, unix.SYS_SYMLINKAT, unix.SYS_TRUNCATE,
	} {
		assert.Contains(t, trapped, nr, "syscall %d (%s) must be trapped", nr, syscallName(int32(nr)))
	}
	for nr, op := range archPathSyscalls() {
		assert.Contains(t, trapped, nr, "arch syscall %d (%s) must be trapped", nr, op.name)
	}
	_, ok := pathOpKindForSyscall("renameat")
	assert.True(t, ok, "renameat is trapped on amd64 and arm64")

	names := make(map[string]bool)
	for nr, op := range seccompPathSyscalls {
		assert.False(t, names[op.name], "duplicate syscall name %q", op.name)
		names[op.name] = true
		assert.Equal(t, op.name, syscallName(int32(nr)))
		if op.hasDst() {
			assert.NotEqual(t, op.src, op.dst, "%s operands must differ", op.name)
		}
	}
	assert.True(t, sort.SliceIsSorted(pathSyscallNumbers(), func(i, j int) bool {
		return pathSyscallNumbers()[i] < pathSyscallNumbers()[j]
	}))
}

func TestPathOpKindForSyscall(t *testing.T) {
	tests := []struct {
		name string
		want pathOpKind
		ok   bool
	}{
		{"openat", pathOpOpen, true},
		{"renameat2", pathOpRename, true},
		{"linkat", pathOpLink, true},
		{"unlinkat", pathOpRemove, true},
		{"mkdirat", pathOpCreate, true},
		{"symlinkat", pathOpCreate, true},
		{"truncate", pathOpTruncate, true},
		{"execve", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kind, ok := pathOpKindForSyscall(tc.name)
			assert.Equal(t, tc.ok, ok)
			if ok {
				assert.Equal(t, tc.want, kind)
			}
		})
	}
}

func TestMatchDeniedWriteTarget(t *testing.T) {
	deny := []denyPathEntry{
		{Path: "/proj/.git/hooks", Mode: denyBoth},
		{Path: "/proj/.git/config", Mode: denyWrite},
		{Path: "/proj/readonly", Mode: denyRead},
	}

	tests := []struct {
		name      string
		path      string
		ancestors bool
		want      bool
	}{
		{"file under both-mode dir", "/proj/.git/hooks/pre-commit", false, true},
		{"the write-denied file", "/proj/.git/config", false, true},
		{"read-only deny allows writes", "/proj/readonly/x", false, false},
		{"sibling", "/proj/.git/index", false, false},
		{"ancestor without ancestor rule", "/proj/.git", false, false},
		{"ancestor with ancestor rule", "/proj/.git", true, true},
		{"ancestor of read-only deny with ancestor rule", "/proj", true, true},
		{"partial name is not an ancestor", "/proj/.gi", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, denied := matchDeniedWriteTarget(tc.path, tc.ancestors, deny)
			assert.Equal(t, tc.want, denied)
		})
	}
}

func TestMatchDeniedMove(t *testing.T) {
	deny := []denyPathEntry{
		{Path: "/proj/.env", Mode: denyBoth},
		{Path: "/proj/.git/hooks", Mode: denyBoth},
		{Path: "/proj/.git/config", Mode: denyRead},
	}

	tests := []struct {
		name     string
		src, dst string
		exchange bool
		want     bool
		wantPath string
	}{
		{"rename protected file away", "/proj/.env", "/proj/env.txt", false, true, "/proj/.env"},
		{"rename onto protected path", "/proj/tmp", "/proj/.env", false, true, "/proj/.env"},
		{"rename into protected dir", "/proj/evil", "/proj/.git/hooks/pre-commit", false, true, "/proj/.git/hooks/pre-commit"},
		{"move ancestor of protected dir away", "/proj/.git", "/proj/gitx", false, true, "/proj/.git"},
		{"move a tree onto the ancestor of a protected path", "/proj/prepared", "/proj/.git", false, true, "/proj/.git"},
		{"read-denied file gets a new name", "/proj/.git/config", "/proj/cfg", false, true, "/proj/.git/config"},
		{"write onto read-only deny is allowed", "/proj/.git/config.lock", "/proj/.git/config", false, false, ""},
		{"exchange with protected path", "/proj/a", "/proj/.env", true, true, "/proj/.env"},
		{"unrelated rename", "/proj/package.json.tmp", "/proj/package.json", false, false, ""},
		{"rename inside node_modules", "/proj/node_modules/.x", "/proj/node_modules/y", false, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, path, denied := matchDeniedMove(tc.src, tc.dst, tc.exchange, deny)
			assert.Equal(t, tc.want, denied)
			assert.Equal(t, tc.wantPath, path)
		})
	}
}

func TestCanonicalPath(t *testing.T) {
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	require.NoError(t, err)

	require.NoError(t, os.MkdirAll(filepath.Join(root, "proj", "node_modules"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "elsewhere", "deep"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "proj", ".env"), []byte("x"), 0o600))
	require.NoError(t, os.Symlink(".env", filepath.Join(root, "proj", "lnk")))
	require.NoError(t, os.Symlink(filepath.Join(root, "elsewhere", "deep"), filepath.Join(root, "proj", "away")))
	require.NoError(t, os.Symlink("..", filepath.Join(root, "proj", "node_modules", "up")))
	require.NoError(t, os.Symlink("loop", filepath.Join(root, "proj", "loop")))

	proj := filepath.Join(root, "proj")
	pid := uint32(os.Getpid())

	tests := []struct {
		name       string
		path       string
		followLeaf bool
		want       string
	}{
		{"plain", proj + "/.env", true, proj + "/.env"},
		{"dot and empty components", proj + "//./node_modules/./", true, proj + "/node_modules"},
		{"leaf symlink followed", proj + "/lnk", true, proj + "/.env"},
		{"leaf symlink kept for rename", proj + "/lnk", false, proj + "/lnk"},
		{"symlink in the middle is always followed", proj + "/node_modules/up/.env", false, proj + "/.env"},
		{"dotdot applies after the symlink target", proj + "/away/../x", true, root + "/elsewhere/x"},
		{"missing leaf keeps its real parent", proj + "/node_modules/up/new.txt", true, proj + "/new.txt"},
		{"missing tail appended lexically", proj + "/nope/a/../b", true, proj + "/nope/b"},
		{"proc self resolves to the notifying process", "/proc/self/cwd/x", true, "/proc/" + strconv.Itoa(os.Getpid()) + "/cwd/x"},
		{"symlink loop stops", proj + "/loop", true, proj + "/loop"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := canonicalPath(pid, tc.path, tc.followLeaf)
			if strings.HasPrefix(tc.want, "/proc/") {
				// /proc/<pid>/cwd is itself a magic link the walker resolves.
				cwd, err := os.Getwd()
				require.NoError(t, err)
				assert.Equal(t, filepath.Join(cwd, "x"), got)
				return
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFollowsLeaf(t *testing.T) {
	open := seccompPathSyscalls[unix.SYS_OPENAT]
	link := seccompPathSyscalls[unix.SYS_LINKAT]
	rename := seccompPathSyscalls[unix.SYS_RENAMEAT2]

	assert.True(t, followsLeaf(open, open.src, unix.O_RDONLY))
	assert.False(t, followsLeaf(open, open.src, unix.O_RDONLY|unix.O_NOFOLLOW))
	assert.False(t, followsLeaf(link, link.src, 0))
	assert.True(t, followsLeaf(link, link.src, unix.AT_SYMLINK_FOLLOW))
	assert.False(t, followsLeaf(link, link.dst, unix.AT_SYMLINK_FOLLOW))
	assert.False(t, followsLeaf(rename, rename.src, 0))
}

func TestDenyMode_Values(t *testing.T) {
	if denyRead == denyWrite {
		t.Error("denyRead and denyWrite should be distinct")
	}
	if denyRead == denyBoth {
		t.Error("denyRead and denyBoth should be distinct")
	}
	if denyWrite == denyBoth {
		t.Error("denyWrite and denyBoth should be distinct")
	}

	// Verify iota ordering
	if denyRead != 0 {
		t.Errorf("denyRead = %d, want 0", denyRead)
	}
	if denyWrite != 1 {
		t.Errorf("denyWrite = %d, want 1", denyWrite)
	}
	if denyBoth != 2 {
		t.Errorf("denyBoth = %d, want 2", denyBoth)
	}
}

func TestWriteAuditEvent(t *testing.T) {
	var buf bytes.Buffer

	evt := auditEvent{
		Type:    auditSeccompDeny,
		Syscall: "openat",
		Path:    "/etc/passwd",
		PID:     1234,
		Message: "blocked",
		Ts:      1700000000,
	}

	err := landlockWriteAuditEvent(&buf, evt)
	if err != nil {
		t.Fatalf("landlockWriteAuditEvent() returned error: %v", err)
	}

	output := buf.String()

	// Should end with newline
	if output[len(output)-1] != '\n' {
		t.Error("output should end with newline")
	}

	// Should be valid JSON
	var decoded auditEvent
	if err := json.Unmarshal([]byte(output), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if decoded.Type != auditSeccompDeny {
		t.Errorf("type = %q, want %q", decoded.Type, auditSeccompDeny)
	}
	if decoded.Syscall != "openat" {
		t.Errorf("syscall = %q, want %q", decoded.Syscall, "openat")
	}
	if decoded.Path != "/etc/passwd" {
		t.Errorf("path = %q, want %q", decoded.Path, "/etc/passwd")
	}
	if decoded.PID != 1234 {
		t.Errorf("pid = %d, want %d", decoded.PID, 1234)
	}
	if decoded.Ts != 1700000000 {
		t.Errorf("ts = %d, want %d", decoded.Ts, 1700000000)
	}
}

func TestWriteAuditEvent_Omitempty(t *testing.T) {
	var buf bytes.Buffer

	evt := auditEvent{
		Type: auditNamespaceUnavailable,
		Ts:   1700000000,
	}

	err := landlockWriteAuditEvent(&buf, evt)
	if err != nil {
		t.Fatalf("landlockWriteAuditEvent() returned error: %v", err)
	}

	output := buf.String()

	// Parse as raw JSON to check which fields are present
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// These fields should be omitted due to omitempty
	omittedFields := []string{"syscall", "path", "pid", "message", "error"}
	for _, field := range omittedFields {
		if _, ok := raw[field]; ok {
			t.Errorf("field %q should be omitted when empty, but was present in output", field)
		}
	}

	// These fields should be present
	requiredFields := []string{"type", "ts"}
	for _, field := range requiredFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("field %q should be present in output", field)
		}
	}
}

func TestIsPathDenied_DenyRead(t *testing.T) {
	deny := []denyPathEntry{
		{Path: "/home/user/.env", Mode: denyRead},
	}

	// DenyRead should block O_RDONLY
	if !isPathDenied("/home/user/.env", unix.O_RDONLY, deny) {
		t.Error("denyRead should block O_RDONLY")
	}

	// DenyRead should block O_RDWR
	if !isPathDenied("/home/user/.env", unix.O_RDWR, deny) {
		t.Error("denyRead should block O_RDWR")
	}

	// DenyRead should allow O_WRONLY
	if isPathDenied("/home/user/.env", unix.O_WRONLY, deny) {
		t.Error("denyRead should allow O_WRONLY")
	}
}

func TestIsPathDenied_DenyWrite(t *testing.T) {
	deny := []denyPathEntry{
		{Path: "/home/user/.env", Mode: denyWrite},
	}

	// DenyWrite should block O_WRONLY
	if !isPathDenied("/home/user/.env", unix.O_WRONLY, deny) {
		t.Error("denyWrite should block O_WRONLY")
	}

	// DenyWrite should block O_RDWR
	if !isPathDenied("/home/user/.env", unix.O_RDWR, deny) {
		t.Error("denyWrite should block O_RDWR")
	}

	// DenyWrite should allow O_RDONLY
	if isPathDenied("/home/user/.env", unix.O_RDONLY, deny) {
		t.Error("denyWrite should allow O_RDONLY")
	}
}

func TestIsPathDenied_DenyBoth(t *testing.T) {
	deny := []denyPathEntry{
		{Path: "/home/user/.env", Mode: denyBoth},
	}

	if !isPathDenied("/home/user/.env", unix.O_RDONLY, deny) {
		t.Error("denyBoth should block O_RDONLY")
	}
	if !isPathDenied("/home/user/.env", unix.O_WRONLY, deny) {
		t.Error("denyBoth should block O_WRONLY")
	}
	if !isPathDenied("/home/user/.env", unix.O_RDWR, deny) {
		t.Error("denyBoth should block O_RDWR")
	}
}

func TestIsPathDenied_ExactMatch(t *testing.T) {
	deny := []denyPathEntry{
		{Path: "/home/user/.env", Mode: denyBoth},
	}

	if !isPathDenied("/home/user/.env", unix.O_RDONLY, deny) {
		t.Error("exact match should be denied")
	}
}

func TestIsPathDenied_NoPartialMatch(t *testing.T) {
	deny := []denyPathEntry{
		{Path: "/home/user/.env", Mode: denyBoth},
	}

	if isPathDenied("/home/user/.envrc", unix.O_RDONLY, deny) {
		t.Error("/home/user/.envrc should NOT match deny /home/user/.env (no partial match)")
	}
}

func TestIsPathDenied_DirectoryPrefix(t *testing.T) {
	deny := []denyPathEntry{
		{Path: "/home/user/.ssh/", Mode: denyBoth},
	}

	if !isPathDenied("/home/user/.ssh/id_rsa", unix.O_RDONLY, deny) {
		t.Error("/home/user/.ssh/id_rsa should match deny /home/user/.ssh/")
	}

	if !isPathDenied("/home/user/.ssh/config", unix.O_WRONLY, deny) {
		t.Error("/home/user/.ssh/config should match deny /home/user/.ssh/")
	}
}

// Deny entries without a trailing slash are treated as "this path or anything
// beneath it" — matching how GetMandatoryDenyPatterns emits entries like
// "/home/user/.ssh" (no slash) that must cover "~/.ssh/id_rsa" too.
func TestIsPathDenied_DirectoryWithoutTrailingSlash(t *testing.T) {
	deny := []denyPathEntry{
		{Path: "/home/user/.ssh", Mode: denyBoth},
	}

	if !isPathDenied("/home/user/.ssh", unix.O_RDONLY, deny) {
		t.Error("exact match on /home/user/.ssh should be denied")
	}
	if !isPathDenied("/home/user/.ssh/id_rsa", unix.O_RDONLY, deny) {
		t.Error("/home/user/.ssh/id_rsa should match deny /home/user/.ssh (no trailing slash)")
	}
	// Must not false-match on similarly-prefixed siblings.
	if isPathDenied("/home/user/.ssh2/id_rsa", unix.O_RDONLY, deny) {
		t.Error("/home/user/.ssh2/id_rsa must NOT match deny /home/user/.ssh (no trailing slash)")
	}
	if isPathDenied("/home/user/.sshfoo", unix.O_RDONLY, deny) {
		t.Error("/home/user/.sshfoo must NOT match deny /home/user/.ssh")
	}
}

func TestIsPathDenied_NoMatch(t *testing.T) {
	deny := []denyPathEntry{
		{Path: "/home/user/.env", Mode: denyBoth},
		{Path: "/home/user/.ssh/", Mode: denyBoth},
	}

	if isPathDenied("/home/user/safe.txt", unix.O_RDONLY, deny) {
		t.Error("/home/user/safe.txt should not match any deny entry")
	}
}

func TestIsExecDenied_Match(t *testing.T) {
	denyExec := []string{"/usr/bin/curl", "/usr/bin/wget"}

	if !isExecDenied("/usr/bin/curl", denyExec) {
		t.Error("/usr/bin/curl should be denied")
	}
}

func TestIsExecDenied_NoMatch(t *testing.T) {
	denyExec := []string{"/usr/bin/curl", "/usr/bin/wget"}

	if isExecDenied("/usr/bin/node", denyExec) {
		t.Error("/usr/bin/node should not be denied")
	}
}

func TestIsExecDenied_DirectoryPrefix(t *testing.T) {
	denyExec := []string{"/usr/bin/"}

	if !isExecDenied("/usr/bin/curl", denyExec) {
		t.Error("/usr/bin/curl should match deny /usr/bin/")
	}
	if !isExecDenied("/usr/bin/node", denyExec) {
		t.Error("/usr/bin/node should match deny /usr/bin/")
	}
	if isExecDenied("/usr/local/bin/node", denyExec) {
		t.Error("/usr/local/bin/node should NOT match deny /usr/bin/")
	}
}

func TestReadPathFromMem(t *testing.T) {
	// Create a temporary file with a null-terminated path string to simulate
	// process memory.
	tmpFile, err := os.CreateTemp("", "test-mem-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			t.Logf("remove temp file: %v", err)
		}
	}()
	defer func() {
		if err := tmpFile.Close(); err != nil {
			t.Logf("close temp file: %v", err)
		}
	}()

	testPath := "/home/user/.env"
	data := append([]byte(testPath), 0) // null-terminated
	// Add some extra bytes after the null to simulate memory contents.
	data = append(data, []byte("garbage data after null")...)

	if _, err := tmpFile.Write(data); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	// Re-open for reading.
	memFd, err := os.Open(tmpFile.Name())
	if err != nil {
		t.Fatalf("open temp file: %v", err)
	}
	defer func() {
		if err := memFd.Close(); err != nil {
			t.Logf("close mem fd: %v", err)
		}
	}()

	result, err := readPathFromMem(memFd, 0)
	if err != nil {
		t.Fatalf("readPathFromMem() error: %v", err)
	}

	if result != testPath {
		t.Errorf("readPathFromMem() = %q, want %q", result, testPath)
	}
}

func TestReadPathFromMem_Offset(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-mem-offset-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			t.Logf("remove temp file: %v", err)
		}
	}()
	defer func() {
		if err := tmpFile.Close(); err != nil {
			t.Logf("close temp file: %v", err)
		}
	}()

	// Write padding, then a null-terminated path at a known offset.
	padding := make([]byte, 100)
	testPath := "/etc/passwd"
	data := append(padding, append([]byte(testPath), 0)...)
	if _, err := tmpFile.Write(data); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	memFd, err := os.Open(tmpFile.Name())
	if err != nil {
		t.Fatalf("open temp file: %v", err)
	}
	defer func() {
		if err := memFd.Close(); err != nil {
			t.Logf("close mem fd: %v", err)
		}
	}()

	result, err := readPathFromMem(memFd, 100)
	if err != nil {
		t.Fatalf("readPathFromMem() error: %v", err)
	}

	if result != testPath {
		t.Errorf("readPathFromMem() = %q, want %q", result, testPath)
	}
}

func TestResolveNotifPath_Absolute(t *testing.T) {
	// Absolute paths need no /proc lookup, whatever the dirfd or pid.
	result, err := resolveNotifPath(1, -100, "/nonexistent-pmg/user/.env", true)
	require.NoError(t, err)
	assert.Equal(t, "/nonexistent-pmg/user/.env", result)

	result, err = resolveNotifPath(1, -100, "/nonexistent-pmg/user/../user/.env", true)
	require.NoError(t, err)
	assert.Equal(t, "/nonexistent-pmg/user/.env", result)
}

func TestResolveNotifPath_EmptyPathNamesDirfd(t *testing.T) {
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	f, err := os.Open(dir)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, f.Close()) })

	result, err := resolveNotifPath(uint32(os.Getpid()), int(f.Fd()), "", false)
	require.NoError(t, err)
	assert.Equal(t, dir, result)
}

func TestResolveNotifPath_AT_FDCWD(t *testing.T) {
	// This test requires /proc/<self>/cwd to be readable.
	pid := os.Getpid()
	cwdLink := fmt.Sprintf("/proc/%d/cwd", pid)
	if _, err := os.Readlink(cwdLink); err != nil {
		t.Skipf("cannot read %s: %v (skipping /proc-dependent test)", cwdLink, err)
	}

	cwd, _ := os.Getwd()
	result, err := resolveNotifPath(uint32(pid), -100, "relative/path", true)
	require.NoError(t, err)
	assert.Equal(t, cwd+"/relative/path", result)
}

func TestDirfdFromArgs(t *testing.T) {
	tests := []struct {
		name string
		val  uint64
		want int
	}{
		{"AT_FDCWD 32-bit", _AT_FDCWD_32, -100},
		{"AT_FDCWD 64-bit", _AT_FDCWD_64, -100},
		{"regular fd 3", 3, 3},
		{"regular fd 0", 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dirfdFromArgs(tt.val)
			if got != tt.want {
				t.Errorf("dirfdFromArgs(0x%x) = %d, want %d", tt.val, got, tt.want)
			}
		})
	}
}

func TestAllowOutbound(t *testing.T) {
	proxyOnly := landlockNetworkPolicy{Lockdown: true, ProxyPort: 54321}
	proxyBind := landlockNetworkPolicy{Lockdown: true, ProxyPort: 54321, AllowBind: true}
	proxyDNS := landlockNetworkPolicy{Lockdown: true, ProxyPort: 54321, AllowDirectDNS: true}
	render := landlockNetworkPolicy{Lockdown: true} // ProxyPort 0: render path, fail closed

	loop := netip.MustParseAddr("127.0.0.1")
	loop6 := netip.MustParseAddr("::1")
	remote := netip.MustParseAddr("203.0.113.9")
	remote6 := netip.MustParseAddr("2001:db8::1")
	resolver := netip.MustParseAddr("127.0.0.53") // systemd-resolved stub
	mapped4 := netip.MustParseAddr("::ffff:127.0.0.1").Unmap()

	tests := []struct {
		name   string
		policy landlockNetworkPolicy
		family uint16
		addr   netip.Addr
		port   uint16
		want   bool
	}{
		{"lockdown off allows everything", landlockNetworkPolicy{}, unix.AF_INET, remote, 443, true},
		{"unix family allowed under lockdown", proxyOnly, unix.AF_UNIX, netip.Addr{}, 0, true},
		{"netlink allowed under lockdown", proxyOnly, unix.AF_NETLINK, netip.Addr{}, 0, true},
		{"vsock denied under lockdown", proxyOnly, unix.AF_VSOCK, netip.Addr{}, 0, false},
		{"proxy port on loopback allowed", proxyOnly, unix.AF_INET, loop, 54321, true},
		{"proxy port on ::1 allowed", proxyOnly, unix.AF_INET6, loop6, 54321, true},
		{"v4-mapped v6 loopback to proxy allowed", proxyOnly, unix.AF_INET6, mapped4, 54321, true},
		{"other loopback port denied without bind", proxyOnly, unix.AF_INET, loop, 8080, false},
		{"other loopback port allowed with bind", proxyBind, unix.AF_INET, loop, 8080, true},
		{"loopback dns denied without direct dns", proxyOnly, unix.AF_INET, resolver, 53, false},
		{"loopback dns allowed with direct dns", proxyDNS, unix.AF_INET, resolver, 53, true},
		{"remote to proxy port still denied", proxyOnly, unix.AF_INET, remote, 54321, false},
		{"remote https denied", proxyOnly, unix.AF_INET, remote, 443, false},
		{"remote v6 denied", proxyOnly, unix.AF_INET6, remote6, 443, false},
		{"remote dns denied by default", proxyOnly, unix.AF_INET, remote, 53, false},
		{"remote dns allowed with direct dns", proxyDNS, unix.AF_INET, remote, 53, true},
		{"render-time policy denies proxy-shaped traffic", render, unix.AF_INET, loop, 443, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.policy.allowOutbound(tc.family, tc.addr, tc.port))
		})
	}
}

// writeMemImage builds a temp file simulating process memory with content at
// the given offset, returned opened for pread-based reads like /proc/pid/mem.
func writeMemImage(t *testing.T, data []byte) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "mem-image-*")
	require.NoError(t, err)
	_, err = f.Write(data)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Logf("close mem image: %v", err)
		}
	})
	return f
}

// sockaddrIPv4Bytes builds a sockaddr_in in memory-image form.
func sockaddrIPv4Bytes(ip string, port uint16) []byte {
	a4 := netip.MustParseAddr(ip).As4()
	b := make([]byte, 16)
	binary.NativeEndian.PutUint16(b[0:2], unix.AF_INET)
	binary.BigEndian.PutUint16(b[2:4], port)
	copy(b[4:8], a4[:])
	return b
}

// sockaddrIPv6Bytes builds a sockaddr_in6 in memory-image form.
func sockaddrIPv6Bytes(ip string, port uint16) []byte {
	a16 := netip.MustParseAddr(ip).As16()
	b := make([]byte, 28)
	binary.NativeEndian.PutUint16(b[0:2], unix.AF_INET6)
	binary.BigEndian.PutUint16(b[2:4], port)
	copy(b[8:24], a16[:])
	return b
}

func TestReadNetPeer(t *testing.T) {
	tests := []struct {
		name       string
		image      []byte
		addrLen    uint64
		wantFamily uint16
		wantAddr   string
		wantPort   uint16
		wantErr    bool
	}{
		{
			name: "ipv4 loopback", image: sockaddrIPv4Bytes("127.0.0.1", 54321), addrLen: 16,
			wantFamily: unix.AF_INET, wantAddr: "127.0.0.1", wantPort: 54321,
		},
		{
			name: "ipv6 remote", image: sockaddrIPv6Bytes("2001:db8::1", 443), addrLen: 28,
			wantFamily: unix.AF_INET6, wantAddr: "2001:db8::1", wantPort: 443,
		},
		{
			name: "v4-mapped v6 unmapped on read", image: sockaddrIPv6Bytes("::ffff:127.0.0.1", 8080), addrLen: 28,
			wantFamily: unix.AF_INET6, wantAddr: "127.0.0.1", wantPort: 8080,
		},
		{
			name: "short sockaddr_in fails", image: sockaddrIPv4Bytes("127.0.0.1", 53), addrLen: 8,
			wantFamily: unix.AF_INET, wantErr: true,
		},
		{
			name: "short sockaddr_in6 fails", image: sockaddrIPv6Bytes("::1", 53), addrLen: 16,
			wantFamily: unix.AF_INET6, wantErr: true,
		},
		{
			name:  "non-inet family parses family only",
			image: append([]byte{byte(unix.AF_UNIX), 0}, []byte("/run/resolver.socket")...), addrLen: 22,
			wantFamily: unix.AF_UNIX,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			memFd := writeMemImage(t, tc.image)
			peer, err := readNetPeer(memFd, 0, tc.addrLen)
			if tc.wantErr {
				require.Error(t, err)
				assert.Equal(t, tc.wantFamily, peer.family)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantFamily, peer.family)
			if tc.wantAddr != "" {
				assert.Equal(t, netip.MustParseAddr(tc.wantAddr), peer.addr)
			}
			assert.Equal(t, tc.wantPort, peer.port)
		})
	}
}

func TestReadNetPeer_UnreadableMemFails(t *testing.T) {
	memFd := writeMemImage(t, nil)
	_, err := readNetPeer(memFd, 0, 16)
	assert.Error(t, err, "empty memory image must fail the family read")
}

var noMemFd = func() *os.File { return nil }

func TestNetSockaddrAddr(t *testing.T) {
	t.Run("connect exposes args directly", func(t *testing.T) {
		notif := &seccompNotification{Data: seccompData{Nr: int32(unix.SYS_CONNECT)}}
		notif.Data.Args[1], notif.Data.Args[2] = 0xdead, 16
		ptr, length, hasDest, ok := netSockaddrAddr(notif, noMemFd)
		assert.True(t, ok)
		assert.True(t, hasDest)
		assert.Equal(t, uint64(0xdead), ptr)
		assert.Equal(t, uint64(16), length)
	})

	t.Run("connected sendto has no destination", func(t *testing.T) {
		notif := &seccompNotification{Data: seccompData{Nr: int32(unix.SYS_SENDTO)}}
		ptr, _, hasDest, ok := netSockaddrAddr(notif, noMemFd)
		assert.True(t, ok)
		assert.False(t, hasDest)
		assert.Equal(t, uint64(0), ptr)
	})

	t.Run("unconnected sendto exposes args", func(t *testing.T) {
		notif := &seccompNotification{Data: seccompData{Nr: int32(unix.SYS_SENDTO)}}
		notif.Data.Args[4], notif.Data.Args[5] = 0xbeef, 16
		ptr, length, hasDest, ok := netSockaddrAddr(notif, noMemFd)
		assert.True(t, ok)
		assert.True(t, hasDest)
		assert.Equal(t, uint64(0xbeef), ptr)
		assert.Equal(t, uint64(16), length)
	})

	t.Run("sendmsg chases msghdr", func(t *testing.T) {
		hdr := make([]byte, 16)
		binary.NativeEndian.PutUint64(hdr[0:8], 0xcafe)
		binary.NativeEndian.PutUint32(hdr[8:12], 16)
		memFd := writeMemImage(t, hdr)

		notif := &seccompNotification{PID: 7, Data: seccompData{Nr: int32(unix.SYS_SENDMSG)}}
		ptr, length, hasDest, ok := netSockaddrAddr(notif, func() *os.File { return memFd })
		assert.True(t, ok)
		assert.True(t, hasDest)
		assert.Equal(t, uint64(0xcafe), ptr)
		assert.Equal(t, uint64(16), length)
	})

	t.Run("sendmsg with no name has no destination", func(t *testing.T) {
		memFd := writeMemImage(t, make([]byte, 16))
		notif := &seccompNotification{PID: 7, Data: seccompData{Nr: int32(unix.SYS_SENDMSG)}}
		_, _, hasDest, ok := netSockaddrAddr(notif, func() *os.File { return memFd })
		assert.True(t, ok)
		assert.False(t, hasDest)
	})

	t.Run("sendmsg with unreadable memory is a policy failure", func(t *testing.T) {
		notif := &seccompNotification{PID: 1, Data: seccompData{Nr: int32(unix.SYS_SENDMSG)}}
		_, _, _, ok := netSockaddrAddr(notif, noMemFd)
		assert.False(t, ok)
	})
}

// TestMemFdForOpensFreshFdPerCall guards the fix for the stale-/proc/pid/mem
// cache bug: an open mem fd pins the task's mm at open() time, so caching
// fds across notifications silently reads a dead address space after execve.
// Every lookup must return a new, independent fd.
func TestMemFdForOpensFreshFdPerCall(t *testing.T) {
	phase := &seccompPhase{}
	pid := uint32(os.Getpid())

	first := phase.memFdFor(pid)
	require.NotNil(t, first)
	defer func() { _ = first.Close() }()

	second := phase.memFdFor(pid)
	require.NotNil(t, second)
	defer func() { _ = second.Close() }()

	assert.NotEqual(t, first.Fd(), second.Fd(), "each lookup must open a fresh fd")

	// Both must read live memory at the same address.
	var probe = [4]byte{0xde, 0xad, 0xbe, 0xef}
	addr := uintptr(unsafe.Pointer(&probe[0]))
	for _, fd := range []*os.File{first, second} {
		buf := make([]byte, 4)
		_, err := fd.ReadAt(buf, int64(addr))
		require.NoError(t, err)
		assert.Equal(t, probe[:], buf)
	}
	runtime.KeepAlive(&probe)
}

func TestReadSyscallFlags(t *testing.T) {
	openat := seccompPathSyscalls[unix.SYS_OPENAT]
	openat2 := seccompPathSyscalls[unix.SYS_OPENAT2]
	renameat2 := seccompPathSyscalls[unix.SYS_RENAMEAT2]
	mkdirat := seccompPathSyscalls[unix.SYS_MKDIRAT]

	assert.Equal(t, unix.O_WRONLY|unix.O_CREAT, readSyscallFlags(openat, [6]uint64{0, 0, uint64(unix.O_WRONLY | unix.O_CREAT)}, nil))
	assert.Equal(t, unix.RENAME_EXCHANGE, readSyscallFlags(renameat2, [6]uint64{0, 0, 0, 0, unix.RENAME_EXCHANGE}, nil))
	assert.Equal(t, 0, readSyscallFlags(mkdirat, [6]uint64{0, 0, 0x777}, nil), "no flags argument")
	assert.Equal(t, unix.O_RDONLY, readSyscallFlags(openat2, [6]uint64{0, 0, 0x1234}, nil), "unreadable open_how defaults to read-only")

	for nr, op := range archPathSyscalls() {
		if op.name == "creat" {
			assert.Equal(t, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC, readSyscallFlags(op, [6]uint64{}, nil), "syscall %d", nr)
		}
	}
}
