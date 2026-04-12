//go:build linux

package platform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"unsafe"

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

func TestBuildSeccompBPFFilter(t *testing.T) {
	prog, err := landlockBuildBPFFilter()
	if err != nil {
		t.Fatalf("landlockBuildBPFFilter() returned error: %v", err)
	}

	if prog == nil {
		t.Fatal("landlockBuildBPFFilter() returned nil")
	}

	if prog.Filter == nil {
		t.Fatal("landlockBuildBPFFilter() returned nil Filter")
	}

	// Expect 7 instructions: 1 load + 4 comparisons + 1 allow + 1 notify
	if prog.Len != 7 {
		t.Errorf("expected 7 instructions, got %d", prog.Len)
	}
}

func TestBuildSeccompBPFFilter_InstructionTypes(t *testing.T) {
	prog, err := landlockBuildBPFFilter()
	if err != nil {
		t.Fatalf("landlockBuildBPFFilter() returned error: %v", err)
	}

	// Access the filter instructions as a slice
	instructions := unsafe.Slice(prog.Filter, prog.Len)

	// First instruction should be BPF_LD | BPF_W | BPF_ABS
	firstCode := instructions[0].Code
	expectedFirst := uint16(unix.BPF_LD | unix.BPF_W | unix.BPF_ABS)
	if firstCode != expectedFirst {
		t.Errorf("first instruction code = 0x%x, want 0x%x (BPF_LD|BPF_W|BPF_ABS)", firstCode, expectedFirst)
	}

	// Second-to-last instruction should be BPF_RET (allow)
	secondToLast := instructions[prog.Len-2]
	expectedRet := uint16(unix.BPF_RET | unix.BPF_K)
	if secondToLast.Code != expectedRet {
		t.Errorf("second-to-last instruction code = 0x%x, want 0x%x (BPF_RET|BPF_K)", secondToLast.Code, expectedRet)
	}
	if secondToLast.K != unix.SECCOMP_RET_ALLOW {
		t.Errorf("second-to-last instruction K = 0x%x, want 0x%x (SECCOMP_RET_ALLOW)", secondToLast.K, unix.SECCOMP_RET_ALLOW)
	}

	// Last instruction should be BPF_RET (notify)
	last := instructions[prog.Len-1]
	if last.Code != expectedRet {
		t.Errorf("last instruction code = 0x%x, want 0x%x (BPF_RET|BPF_K)", last.Code, expectedRet)
	}
	if last.K != unix.SECCOMP_RET_USER_NOTIF {
		t.Errorf("last instruction K = 0x%x, want 0x%x (SECCOMP_RET_USER_NOTIF)", last.K, unix.SECCOMP_RET_USER_NOTIF)
	}
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
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

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
	defer memFd.Close()

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
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

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
	defer memFd.Close()

	result, err := readPathFromMem(memFd, 100)
	if err != nil {
		t.Fatalf("readPathFromMem() error: %v", err)
	}

	if result != testPath {
		t.Errorf("readPathFromMem() = %q, want %q", result, testPath)
	}
}

func TestResolveNotifPath_Absolute(t *testing.T) {
	// Absolute paths should be returned cleaned, regardless of dirfd/pid.
	result, err := resolveNotifPath(1, -100, "/home/user/.env")
	if err != nil {
		t.Fatalf("resolveNotifPath() error: %v", err)
	}
	if result != "/home/user/.env" {
		t.Errorf("resolveNotifPath() = %q, want %q", result, "/home/user/.env")
	}

	// With .. components that should be cleaned.
	result, err = resolveNotifPath(1, -100, "/home/user/../user/.env")
	if err != nil {
		t.Fatalf("resolveNotifPath() error: %v", err)
	}
	if result != "/home/user/.env" {
		t.Errorf("resolveNotifPath() = %q, want %q", result, "/home/user/.env")
	}
}

func TestResolveNotifPath_AT_FDCWD(t *testing.T) {
	// This test requires /proc/<self>/cwd to be readable.
	pid := os.Getpid()
	cwdLink := fmt.Sprintf("/proc/%d/cwd", pid)
	if _, err := os.Readlink(cwdLink); err != nil {
		t.Skipf("cannot read %s: %v (skipping /proc-dependent test)", cwdLink, err)
	}

	cwd, _ := os.Getwd()
	result, err := resolveNotifPath(uint32(pid), -100, "relative/path")
	if err != nil {
		t.Fatalf("resolveNotifPath() error: %v", err)
	}

	expected := cwd + "/relative/path"
	if result != expected {
		t.Errorf("resolveNotifPath() = %q, want %q", result, expected)
	}
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

func TestClassifyOpenFlags_Openat(t *testing.T) {
	tests := []struct {
		name     string
		flags    uint64
		expected int
	}{
		{"O_RDONLY", uint64(unix.O_RDONLY), unix.O_RDONLY},
		{"O_WRONLY", uint64(unix.O_WRONLY), unix.O_WRONLY},
		{"O_RDWR", uint64(unix.O_RDWR), unix.O_RDWR},
		{"O_WRONLY|O_CREAT", uint64(unix.O_WRONLY | unix.O_CREAT), unix.O_WRONLY},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := [6]uint64{0, 0, tt.flags, 0, 0, 0}
			got := classifyOpenFlags(int32(unix.SYS_OPENAT), args, nil)
			if got != tt.expected {
				t.Errorf("classifyOpenFlags() = %d, want %d", got, tt.expected)
			}
		})
	}
}
