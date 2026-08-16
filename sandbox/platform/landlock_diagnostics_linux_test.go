//go:build linux

package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"

	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func denyEvent(syscall, path, access, comm string) capturedAuditEvent {
	return capturedAuditEvent{
		auditEvent: auditEvent{
			Type:    auditSeccompDeny,
			Syscall: syscall,
			Path:    path,
			Access:  access,
			Comm:    comm,
			PID:     123,
		},
		raw: `{"type":"seccomp_deny"}`,
	}
}

func TestExtractLandlockViolations(t *testing.T) {
	tests := []struct {
		name   string
		events []capturedAuditEvent
		want   []sandbox.Violation
	}{
		{
			name:   "read denial maps to fs_read",
			events: []capturedAuditEvent{denyEvent("openat", "/home/dev/.ssh/id_rsa", "read", "node")},
			want: []sandbox.Violation{{
				Kind:      sandbox.ViolationKindFSRead,
				RawKind:   "openat",
				Target:    "/home/dev/.ssh/id_rsa",
				Process:   "node",
				RawLog:    `{"type":"seccomp_deny"}`,
				RuleLabel: "read access denied: /home/dev/.ssh/id_rsa",
			}},
		},
		{
			name:   "write denial maps to fs_write",
			events: []capturedAuditEvent{denyEvent("openat2", "/home/dev/project/.env", "write", "npm")},
			want: []sandbox.Violation{{
				Kind:      sandbox.ViolationKindFSWrite,
				RawKind:   "openat2",
				Target:    "/home/dev/project/.env",
				Process:   "npm",
				RawLog:    `{"type":"seccomp_deny"}`,
				RuleLabel: "write access denied: /home/dev/project/.env",
			}},
		},
		{
			name:   "exec denial maps to exec regardless of access",
			events: []capturedAuditEvent{denyEvent("execve", "/usr/bin/curl", "", "bash")},
			want: []sandbox.Violation{{
				Kind:      sandbox.ViolationKindExec,
				RawKind:   "execve",
				Target:    "/usr/bin/curl",
				Process:   "bash",
				RawLog:    `{"type":"seccomp_deny"}`,
				RuleLabel: "process execution denied: /usr/bin/curl",
			}},
		},
		{
			name:   "execveat also maps to exec",
			events: []capturedAuditEvent{denyEvent("execveat", "/usr/bin/nc", "", "sh")},
			want: []sandbox.Violation{{
				Kind:      sandbox.ViolationKindExec,
				RawKind:   "execveat",
				Target:    "/usr/bin/nc",
				Process:   "sh",
				RawLog:    `{"type":"seccomp_deny"}`,
				RuleLabel: "process execution denied: /usr/bin/nc",
			}},
		},
		{
			name: "operational events are skipped",
			events: []capturedAuditEvent{
				{auditEvent: auditEvent{Type: auditNamespaceUnavailable, Message: "clone failed"}, raw: "{}"},
				{auditEvent: auditEvent{Type: auditMemFdOpenFailed, PID: 1, Error: "EACCES"}, raw: "{}"},
			},
			want: []sandbox.Violation{},
		},
		{
			name: "identical kind and target deduplicated",
			events: []capturedAuditEvent{
				denyEvent("openat", "/home/dev/.netrc", "read", "node"),
				denyEvent("openat", "/home/dev/.netrc", "read", "node"),
				denyEvent("openat2", "/home/dev/.netrc", "read", "node"),
			},
			want: []sandbox.Violation{{
				Kind:      sandbox.ViolationKindFSRead,
				RawKind:   "openat",
				Target:    "/home/dev/.netrc",
				Process:   "node",
				RawLog:    `{"type":"seccomp_deny"}`,
				RuleLabel: "read access denied: /home/dev/.netrc",
			}},
		},
		{
			name: "rule target populated from rule_path",
			events: []capturedAuditEvent{{
				auditEvent: auditEvent{
					Type:     auditSeccompDeny,
					Syscall:  "openat",
					Path:     "/home/dev/.ssh/id_rsa",
					Access:   "read",
					RulePath: "/home/dev/.ssh",
					Comm:     "node",
				},
				raw: "{}",
			}},
			want: []sandbox.Violation{{
				Kind:       sandbox.ViolationKindFSRead,
				RawKind:    "openat",
				Target:     "/home/dev/.ssh/id_rsa",
				RuleTarget: "/home/dev/.ssh",
				Process:    "node",
				RawLog:     "{}",
				RuleLabel:  "read access denied: /home/dev/.ssh/id_rsa",
			}},
		},
		{
			name: "connect denial maps to network_connect",
			events: []capturedAuditEvent{{
				auditEvent: auditEvent{
					Type:    auditNetworkDeny,
					Syscall: "connect",
					Path:    "203.0.113.9:443",
					Comm:    "node",
				},
				raw: `{"type":"network_deny"}`,
			}},
			want: []sandbox.Violation{{
				Kind:      sandbox.ViolationKindNetworkConnect,
				RawKind:   "connect",
				Target:    "203.0.113.9:443",
				Process:   "node",
				RawLog:    `{"type":"network_deny"}`,
				RuleLabel: "direct network access blocked by network_via_proxy_only (203.0.113.9:443) — traffic must flow through the PMG proxy (a tool may have ignored HTTP_PROXY/HTTPS_PROXY)",
			}},
		},
		{
			name: "connect and sendto denials to one target deduplicate",
			events: []capturedAuditEvent{
				{
					auditEvent: auditEvent{Type: auditNetworkDeny, Syscall: "connect", Path: "8.8.8.8:53", Comm: "node"},
					raw:        "{}",
				},
				{
					auditEvent: auditEvent{Type: auditNetworkDeny, Syscall: "sendto", Path: "8.8.8.8:53", Comm: "node"},
					raw:        "{}",
				},
			},
			want: []sandbox.Violation{{
				Kind:      sandbox.ViolationKindNetworkConnect,
				RawKind:   "connect",
				Target:    "8.8.8.8:53",
				Process:   "node",
				RawLog:    "{}",
				RuleLabel: "direct network access blocked by network_via_proxy_only (8.8.8.8:53) — traffic must flow through the PMG proxy (a tool may have ignored HTTP_PROXY/HTTPS_PROXY)",
			}},
		},
		{
			name:   "unknown syscall maps to generic_deny",
			events: []capturedAuditEvent{denyEvent("syscall_999", "/tmp/x", "", "node")},
			want: []sandbox.Violation{{
				Kind:      sandbox.ViolationKindGenericDeny,
				RawKind:   "syscall_999",
				Target:    "/tmp/x",
				Process:   "node",
				RawLog:    `{"type":"seccomp_deny"}`,
				RuleLabel: "sandbox denied access to /tmp/x",
			}},
		},
		{
			name: "same target different kind kept",
			events: []capturedAuditEvent{
				denyEvent("openat", "/home/dev/.npmrc", "read", "node"),
				denyEvent("openat", "/home/dev/.npmrc", "write", "node"),
			},
			want: []sandbox.Violation{
				{
					Kind:      sandbox.ViolationKindFSRead,
					RawKind:   "openat",
					Target:    "/home/dev/.npmrc",
					Process:   "node",
					RawLog:    `{"type":"seccomp_deny"}`,
					RuleLabel: "read access denied: /home/dev/.npmrc",
				},
				{
					Kind:      sandbox.ViolationKindFSWrite,
					RawKind:   "openat",
					Target:    "/home/dev/.npmrc",
					Process:   "node",
					RawLog:    `{"type":"seccomp_deny"}`,
					RuleLabel: "write access denied: /home/dev/.npmrc",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, extractLandlockViolations(tc.events))
		})
	}
}

func TestCaptureAuditEvents(t *testing.T) {
	input := `{"type":"seccomp_deny","syscall":"openat","path":"/home/dev/.ssh/id_rsa","access":"read","comm":"node","pid":42,"ts":0}

not-json
{"type":"namespace_isolation_unavailable","message":"clone failed","ts":0}
`

	s := &landlockSandbox{}
	s.captureAuditEvents(strings.NewReader(input))

	require.Len(t, s.auditEvents, 2)
	assert.Equal(t, auditSeccompDeny, s.auditEvents[0].Type)
	assert.Equal(t, "/home/dev/.ssh/id_rsa", s.auditEvents[0].Path)
	assert.Equal(t, "read", s.auditEvents[0].Access)
	assert.Equal(t, "node", s.auditEvents[0].Comm)
	assert.Contains(t, s.auditEvents[0].raw, `"syscall":"openat"`)
	assert.Equal(t, auditNamespaceUnavailable, s.auditEvents[1].Type)
}

func TestCaptureAuditEventsBounded(t *testing.T) {
	var sb strings.Builder
	for i := range landlockAuditEventCap + 10 {
		fmt.Fprintf(&sb, `{"type":"seccomp_deny","syscall":"openat","path":"/tmp/f%d","ts":0}`+"\n", i)
	}

	s := &landlockSandbox{}
	s.captureAuditEvents(strings.NewReader(sb.String()))

	assert.Len(t, s.auditEvents, landlockAuditEventCap)
}

// A tight retry loop on one denied path must not fill the buffer and evict a
// later distinct denial (dedupe happens before the cap).
func TestCaptureAuditEventsDedupesDenials(t *testing.T) {
	var sb strings.Builder
	for range landlockAuditEventCap + 10 {
		sb.WriteString(`{"type":"seccomp_deny","syscall":"openat","path":"/tmp/.env","access":"write","ts":1}` + "\n")
	}
	sb.WriteString(`{"type":"seccomp_deny","syscall":"execve","path":"/usr/bin/curl","ts":1}` + "\n")

	s := &landlockSandbox{}
	s.captureAuditEvents(strings.NewReader(sb.String()))

	require.Len(t, s.auditEvents, 2)
	assert.Equal(t, "/tmp/.env", s.auditEvents[0].Path)
	assert.Equal(t, "/usr/bin/curl", s.auditEvents[1].Path)
}

// An O_RDWR open denied by a read-only rule must be labeled a read denial so
// the suggested override (--sandbox-allow read=...) actually unblocks it;
// allowing write would prune only deny_write entries.
func TestDenyAccessLabelReportsFiredRule(t *testing.T) {
	deny := []denyPathEntry{{Path: "/home/dev/.npmrc", Mode: denyRead}}

	entry, denied := matchDeniedPath("/home/dev/.npmrc", unix.O_RDWR, deny)
	require.True(t, denied)
	assert.Equal(t, "read", denyAccessLabel(entry.Mode, unix.O_RDWR))

	assert.Equal(t, "write", denyAccessLabel(denyWrite, unix.O_RDWR))
	assert.Equal(t, "read", denyAccessLabel(denyBoth, unix.O_RDONLY))
	assert.Equal(t, "write", denyAccessLabel(denyBoth, unix.O_RDWR))
}

func TestBestEffortViolationNilOnSuccess(t *testing.T) {
	done := make(chan struct{})
	close(done)
	s := &landlockSandbox{
		auditDone:   done,
		auditEvents: []capturedAuditEvent{denyEvent("openat", "/tmp/.env", "read", "node")},
	}

	report, err := s.BestEffortViolation(nil)
	require.NoError(t, err)
	assert.Nil(t, report)
}

func TestBestEffortViolationNilWithoutExecute(t *testing.T) {
	s := &landlockSandbox{}

	report, err := s.BestEffortViolation(errors.New("exit status 1"))
	require.NoError(t, err)
	assert.Nil(t, report)
}

func TestBestEffortViolationNilWithoutDenials(t *testing.T) {
	done := make(chan struct{})
	close(done)
	s := &landlockSandbox{
		policyName: "test-policy",
		auditDone:  done,
		auditEvents: []capturedAuditEvent{
			{auditEvent: auditEvent{Type: auditNamespaceUnavailable, Message: "clone failed"}, raw: "{}"},
		},
	}

	report, err := s.BestEffortViolation(errors.New("exit status 1"))
	require.NoError(t, err)
	assert.Nil(t, report)
}

// TestBestEffortViolationSocketFlow drives the real Execute socket plumbing:
// a fake helper dials the audit socket, writes deny events through the real
// serializer, and the driver must surface them as a violation report.
func TestBestEffortViolationSocketFlow(t *testing.T) {
	s := &landlockSandbox{abi: newLandlockABI(1)}
	defer func() {
		require.NoError(t, s.Close())
	}()

	cmd := exec.Command("/bin/true")
	policy := &sandbox.SandboxPolicy{Name: "test-policy"}

	_, err := s.Execute(context.Background(), cmd, policy, &sandbox.ExecutionContext{})
	require.NoError(t, err)

	conn, err := net.Dial("unix", s.socketPath)
	require.NoError(t, err)

	require.NoError(t, landlockWriteAuditEvent(conn, auditEvent{
		Type:    auditSeccompDeny,
		Syscall: "openat",
		Path:    "/home/dev/.ssh/id_rsa",
		Access:  "read",
		Comm:    "node",
		PID:     42,
	}))
	require.NoError(t, landlockWriteAuditEvent(conn, auditEvent{
		Type:    auditSeccompDeny,
		Syscall: "execve",
		Path:    "/usr/bin/curl",
		Comm:    "bash",
		PID:     43,
	}))
	require.NoError(t, conn.Close())

	report, err := s.BestEffortViolation(errors.New("exit status 2"))
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.Equal(t, sandbox.DriverLandlock, report.SandboxName)
	assert.Equal(t, "test-policy", report.PolicyName)
	require.Len(t, report.Violations, 2)

	assert.Equal(t, sandbox.ViolationKindFSRead, report.Violations[0].Kind)
	assert.Equal(t, "/home/dev/.ssh/id_rsa", report.Violations[0].Target)
	assert.Equal(t, "node", report.Violations[0].Process)
	assert.Equal(t, "read access denied: /home/dev/.ssh/id_rsa", report.Violations[0].RuleLabel)

	assert.Equal(t, sandbox.ViolationKindExec, report.Violations[1].Kind)
	assert.Equal(t, "/usr/bin/curl", report.Violations[1].Target)
}

// The helper may die before ever dialing the audit socket; BestEffortViolation
// must return within the drain-wait guard instead of hanging on Accept.
func TestBestEffortViolationHelperNeverConnected(t *testing.T) {
	s := &landlockSandbox{abi: newLandlockABI(1)}
	defer func() {
		require.NoError(t, s.Close())
	}()

	cmd := exec.Command("/bin/true")
	policy := &sandbox.SandboxPolicy{Name: "test-policy"}

	_, err := s.Execute(context.Background(), cmd, policy, &sandbox.ExecutionContext{})
	require.NoError(t, err)

	report, err := s.BestEffortViolation(errors.New("exit status 2"))
	require.NoError(t, err)
	assert.Nil(t, report)
}
