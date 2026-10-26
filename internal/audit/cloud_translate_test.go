package audit

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	"github.com/safedep/pmg/internal/runerror"
	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// testSink is a cloudSink with no emitter, suitable for testing translation only.
var testSink = &cloudSink{invocationID: "test-invocation"}

func TestTranslateMalwareBlocked(t *testing.T) {
	event := AuditEvent{
		Type:           EventTypeMalwareBlocked,
		PackageVersion: testPackageVersion("evil-pkg", "1.2.3", "npm"),
		AnalysisID:     "analysis-123",
		IsMalware:      true,
		IsVerified:     true,
	}

	results := testSink.translateToPmgEvents(event)
	require.Len(t, results, 1)
	result := results[0]

	assert.Equal(t, controltowerv1.PmgEventType_PMG_EVENT_TYPE_PACKAGE_DECISION, result.GetEventType())
	require.True(t, result.HasPackageDecision())

	decision := result.GetPackageDecision()
	assert.Equal(t, controltowerv1.PmgPackageAction_PMG_PACKAGE_ACTION_BLOCKED, decision.GetAction())
	assert.Equal(t, "analysis-123", decision.GetAnalysisId())
	assert.True(t, decision.GetIsMalware())
	assert.True(t, decision.GetIsVerified())
	assert.NotNil(t, decision.GetPackageVersion())
}

func TestTranslateMalwareConfirmed(t *testing.T) {
	event := AuditEvent{
		Type:           EventTypeMalwareConfirmed,
		PackageVersion: testPackageVersion("suspect-pkg", "2.0.0", "npm"),
		AnalysisID:     "analysis-456",
		IsMalware:      false,
		IsVerified:     false,
	}

	results := testSink.translateToPmgEvents(event)
	require.Len(t, results, 1)
	result := results[0]

	assert.Equal(t, controltowerv1.PmgEventType_PMG_EVENT_TYPE_PACKAGE_DECISION, result.GetEventType())
	require.True(t, result.HasPackageDecision())

	decision := result.GetPackageDecision()
	assert.Equal(t, controltowerv1.PmgPackageAction_PMG_PACKAGE_ACTION_CONFIRMED, decision.GetAction())
	assert.Equal(t, "analysis-456", decision.GetAnalysisId())
	assert.False(t, decision.GetIsMalware())
	assert.False(t, decision.GetIsVerified())
	assert.False(t, decision.GetIsVerified())
}

func TestTranslateCooldownSkipped(t *testing.T) {
	event := AuditEvent{
		Type:           EventTypeCooldownSkipped,
		PackageVersion: testPackageVersion("exempt-pkg", "1.0.0", "npm"),
		Reason:         "dependency_cooldown.skip",
	}

	results := testSink.translateToPmgEvents(event)
	require.Len(t, results, 1)
	result := results[0]

	assert.Equal(t, controltowerv1.PmgEventType_PMG_EVENT_TYPE_PACKAGE_DECISION, result.GetEventType())
	require.True(t, result.HasPackageDecision())

	decision := result.GetPackageDecision()
	assert.Equal(t, controltowerv1.PmgPackageAction_PMG_PACKAGE_ACTION_COOLDOWN_SKIPPED, decision.GetAction())
	require.NotNil(t, decision.GetPackageVersion(), "package_version must be propagated to the cloud sink")
	assert.Equal(t, "exempt-pkg", decision.GetPackageVersion().GetPackage().GetName())
	assert.Equal(t, "1.0.0", decision.GetPackageVersion().GetVersion())
}

func TestTranslateInstallTrustedAllowed(t *testing.T) {
	event := AuditEvent{
		Type:           EventTypeInstallTrustedAllowed,
		PackageVersion: testPackageVersion("trusted-pkg", "2.0.0", "npm"),
	}

	results := testSink.translateToPmgEvents(event)
	require.Len(t, results, 1)
	result := results[0]

	assert.Equal(t, controltowerv1.PmgEventType_PMG_EVENT_TYPE_PACKAGE_DECISION, result.GetEventType())
	require.True(t, result.HasPackageDecision())

	decision := result.GetPackageDecision()
	assert.Equal(t, controltowerv1.PmgPackageAction_PMG_PACKAGE_ACTION_TRUSTED, decision.GetAction())
	require.NotNil(t, decision.GetPackageVersion())
	assert.Equal(t, "trusted-pkg", decision.GetPackageVersion().GetPackage().GetName())
}

func TestTranslateInsecureBypassReturnsEmpty(t *testing.T) {
	event := AuditEvent{
		Type: EventTypeInstallInsecureBypass,
	}

	results := testSink.translateToPmgEvents(event)
	assert.Empty(t, results)
}

func TestTranslateSandboxOverride(t *testing.T) {
	event := AuditEvent{
		Type:        EventTypeSandboxOverride,
		ProfileName: "strict",
		Overrides: []map[string]string{
			{"type": "read", "value": "/tmp"},
			{"type": "write", "value": "/var/log"},
		},
	}

	results := testSink.translateToPmgEvents(event)
	require.Len(t, results, 1)
	result := results[0]

	assert.Equal(t, controltowerv1.PmgEventType_PMG_EVENT_TYPE_SANDBOX_OVERRIDE, result.GetEventType())
	require.True(t, result.HasSandboxOverride())

	override := result.GetSandboxOverride()
	assert.Equal(t, "strict", override.GetSandboxProfile())
	assert.Equal(t, []string{"read=/tmp", "write=/var/log"}, override.GetOverrides())
}

func sandboxViolationEvent(cleanExit bool, violations ...SandboxViolation) AuditEvent {
	return AuditEvent{
		Type: EventTypeSandboxViolation,
		SandboxViolations: SandboxViolationReport{
			Driver:     sandbox.DriverSeatbelt,
			Profile:    "npm-restrictive",
			CleanExit:  cleanExit,
			Violations: violations,
		},
	}
}

func TestTranslateSandboxViolation(t *testing.T) {
	port := uint16(443)
	results := testSink.translateToPmgEvents(sandboxViolationEvent(true,
		SandboxViolation{Kind: sandbox.ViolationKindFSRead, Path: "/Users/dev/.ssh/id_rsa", Rule: "/Users/dev/.ssh", Process: "node", Count: 3},
		SandboxViolation{Kind: sandbox.ViolationKindNetworkConnect, Host: "1.2.3.4", Port: &port, Count: 1},
		SandboxViolation{Kind: sandbox.ViolationKindExec, Executable: "/usr/bin/curl", Process: "sh", Count: 2},
	))
	require.Len(t, results, 1)
	result := results[0]

	assert.Equal(t, controltowerv1.PmgEventType_PMG_EVENT_TYPE_SANDBOX_VIOLATION, result.GetEventType())
	require.True(t, result.HasSandboxViolationReport())

	report := result.GetSandboxViolationReport()
	assert.Equal(t, controltowerv1.PmgSandboxDriver_PMG_SANDBOX_DRIVER_SEATBELT, report.GetDriver())
	assert.Equal(t, "npm-restrictive", report.GetSandboxProfile())
	assert.Equal(t, controltowerv1.PmgSandboxExitStatus_PMG_SANDBOX_EXIT_STATUS_SUCCESS, report.GetExitStatus())
	assert.Equal(t, uint32(3), report.GetDistinctCount())
	require.Len(t, report.GetViolations(), 3)

	read := report.GetViolations()[0]
	assert.Equal(t, controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_FILESYSTEM_READ, read.GetKind())
	assert.Equal(t, "/Users/dev/.ssh/id_rsa", read.GetPath())
	assert.False(t, read.HasExecutable())
	assert.False(t, read.HasHost())
	assert.Equal(t, "/Users/dev/.ssh", read.GetRule())
	assert.Equal(t, "node", read.GetProcess())
	assert.Equal(t, uint32(3), read.GetCount())

	connect := report.GetViolations()[1]
	assert.Equal(t, controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_NETWORK_CONNECT, connect.GetKind())
	assert.Equal(t, "1.2.3.4", connect.GetHost())
	assert.Equal(t, uint32(443), connect.GetPort())
	assert.False(t, connect.HasPath())
	assert.False(t, connect.HasRule(), "an unknown rule is unset, not empty")
	assert.False(t, connect.HasProcess(), "an unknown process is unset, not empty")

	exec := report.GetViolations()[2]
	assert.Equal(t, controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_EXEC, exec.GetKind())
	assert.Equal(t, "/usr/bin/curl", exec.GetExecutable())
	assert.False(t, exec.HasPath())
}

func TestTranslateSandboxViolationOfAFailedRun(t *testing.T) {
	report := testSink.translateToPmgEvents(sandboxViolationEvent(false,
		SandboxViolation{Kind: sandbox.ViolationKindFSWrite, Path: "/etc/hosts", Count: 1},
	))[0].GetSandboxViolationReport()
	assert.Equal(t, controltowerv1.PmgSandboxExitStatus_PMG_SANDBOX_EXIT_STATUS_FAILED, report.GetExitStatus())
}

// The proto requires exactly one of path, executable and host on each entry.
func TestTranslateSandboxViolationSetsExactlyOneTarget(t *testing.T) {
	zero, https := uint16(0), uint16(443)

	tests := []struct {
		name      string
		violation SandboxViolation
		wantKept  bool
		wantPort  *uint32
	}{
		{"path", SandboxViolation{Kind: sandbox.ViolationKindFSRead, Path: "/x"}, true, nil},
		{"executable", SandboxViolation{Kind: sandbox.ViolationKindExec, Executable: "/usr/bin/curl"}, true, nil},
		{"host and port", SandboxViolation{Kind: sandbox.ViolationKindNetworkConnect, Host: "1.2.3.4", Port: &https}, true, proto.Uint32(443)},
		{"bind of any port", SandboxViolation{Kind: sandbox.ViolationKindNetworkBind, Host: "*", Port: &zero}, true, proto.Uint32(0)},
		{"host without a port", SandboxViolation{Kind: sandbox.ViolationKindNetworkConnect, Host: "1.2.3.4"}, true, nil},
		{"no target", SandboxViolation{Kind: sandbox.ViolationKindFSRead}, false, nil},
		{"two targets", SandboxViolation{Kind: sandbox.ViolationKindFSRead, Path: "/x", Host: "1.2.3.4"}, false, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keep := SandboxViolation{Kind: sandbox.ViolationKindFSRead, Path: "/kept", Count: 1}
			report := testSink.translateToPmgEvents(sandboxViolationEvent(true, tc.violation, keep))[0].GetSandboxViolationReport()

			assert.Equal(t, uint32(2), report.GetDistinctCount())
			if !tc.wantKept {
				require.Len(t, report.GetViolations(), 1)
				assert.Equal(t, "/kept", report.GetViolations()[0].GetPath())
				return
			}

			require.Len(t, report.GetViolations(), 2)
			v := report.GetViolations()[0]
			targets := 0
			for _, set := range []bool{v.HasPath(), v.HasExecutable(), v.HasHost()} {
				if set {
					targets++
				}
			}
			assert.Equal(t, 1, targets)
			if tc.wantPort == nil {
				assert.False(t, v.HasPort())
			} else {
				require.True(t, v.HasPort())
				assert.Equal(t, *tc.wantPort, v.GetPort())
			}
		})
	}
}

// A report must hold at least one entry, so a run with no usable target
// sends no event.
func TestTranslateSandboxViolationWithNoUsableEntrySendsNothing(t *testing.T) {
	results := testSink.translateToPmgEvents(sandboxViolationEvent(true,
		SandboxViolation{Kind: sandbox.ViolationKindFSRead},
		SandboxViolation{Kind: sandbox.ViolationKindFSRead, Path: "/" + strings.Repeat("a", maxSandboxViolationPath)},
	))
	assert.Empty(t, results)
}

// Control Tower rejects the whole sync batch when one event breaks a proto
// bound, so the translation must never produce such an event.
func TestTranslateSandboxViolationStaysInsideTheBounds(t *testing.T) {
	entries := func(n, pathLen int) []SandboxViolation {
		out := make([]SandboxViolation, n)
		for i := range out {
			out[i] = SandboxViolation{Kind: sandbox.ViolationKindFSRead, Path: fmt.Sprintf("/%0*d", pathLen-1, i), Count: 1}
		}
		return out
	}

	tests := []struct {
		name         string
		violations   []SandboxViolation
		wantKept     int
		wantDistinct uint32
	}{
		{
			name:         "count cap",
			violations:   entries(150, 20),
			wantKept:     maxSandboxViolations,
			wantDistinct: 150,
		},
		{
			name:         "byte budget",
			violations:   entries(50, 4000),
			wantKept:     sandboxViolationBudget / 4000,
			wantDistinct: 50,
		},
		{
			name: "a path over its bound is dropped",
			violations: []SandboxViolation{
				{Kind: sandbox.ViolationKindFSRead, Path: "/" + strings.Repeat("a", maxSandboxViolationPath), Count: 1},
				{Kind: sandbox.ViolationKindFSRead, Path: "/etc/hosts", Count: 1},
			},
			wantKept:     1,
			wantDistinct: 2,
		},
		{
			name: "a host over its bound is dropped",
			violations: []SandboxViolation{
				{Kind: sandbox.ViolationKindNetworkConnect, Host: strings.Repeat("h", maxSandboxViolationHost+1), Count: 1},
				{Kind: sandbox.ViolationKindNetworkConnect, Host: "1.2.3.4", Count: 1},
			},
			wantKept:     1,
			wantDistinct: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			event := AuditEvent{
				Type:              EventTypeSandboxViolation,
				SandboxViolations: SandboxViolationReport{Driver: sandbox.DriverLandlock, Violations: tc.violations},
			}

			report := testSink.translateToPmgEvents(event)[0].GetSandboxViolationReport()
			assert.Len(t, report.GetViolations(), tc.wantKept)
			assert.Equal(t, tc.wantDistinct, report.GetDistinctCount())
			for _, v := range report.GetViolations() {
				assert.LessOrEqual(t, len(v.GetPath()), maxSandboxViolationPath)
				assert.LessOrEqual(t, len(v.GetHost()), maxSandboxViolationHost)
			}
		})
	}
}

func TestTranslateSandboxViolationCleansStrings(t *testing.T) {
	event := AuditEvent{
		Type: EventTypeSandboxViolation,
		SandboxViolations: SandboxViolationReport{
			Driver:  sandbox.DriverLandlock,
			Profile: strings.Repeat("p", maxSandboxProfile+10),
			Violations: []SandboxViolation{{
				Kind:    sandbox.ViolationKindFSRead,
				Path:    "/tmp/bad-\xff-name",
				Process: strings.Repeat("é", maxSandboxViolationProcess),
			}},
		},
	}

	report := testSink.translateToPmgEvents(event)[0].GetSandboxViolationReport()
	assert.Len(t, report.GetSandboxProfile(), maxSandboxProfile)

	v := report.GetViolations()[0]
	assert.True(t, utf8.ValidString(v.GetPath()))
	assert.Equal(t, "/tmp/bad-"+string(utf8.RuneError)+"-name", v.GetPath())
	assert.True(t, utf8.ValidString(v.GetProcess()), "a cut must not split a character")
	assert.LessOrEqual(t, len(v.GetProcess()), maxSandboxViolationProcess)
	assert.Equal(t, uint32(1), v.GetCount(), "the proto requires a count of at least 1")
}

func TestTranslateSandboxViolationLimitsTheCount(t *testing.T) {
	cases := []struct {
		name  string
		count int
		want  uint32
	}{
		{"zero", 0, 1},
		{"in range", 7, 7},
		{"wraps to zero as uint32", 1 << 32, math.MaxUint32},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			event := AuditEvent{
				Type: EventTypeSandboxViolation,
				SandboxViolations: SandboxViolationReport{
					Driver:     sandbox.DriverBubblewrap,
					Violations: []SandboxViolation{{Kind: sandbox.ViolationKindFSRead, Path: "/etc/hosts", Count: tc.count}},
				},
			}

			report := testSink.translateToPmgEvents(event)[0].GetSandboxViolationReport()
			assert.Equal(t, tc.want, report.GetViolations()[0].GetCount())
		})
	}
}

func TestMapSandboxViolationKind(t *testing.T) {
	tests := []struct {
		kind sandbox.ViolationKind
		want controltowerv1.PmgSandboxViolationKind
	}{
		{sandbox.ViolationKindFSRead, controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_FILESYSTEM_READ},
		{sandbox.ViolationKindFSWrite, controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_FILESYSTEM_WRITE},
		{sandbox.ViolationKindFSDeleteOrRename, controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_FILESYSTEM_DELETE_OR_RENAME},
		{sandbox.ViolationKindExec, controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_EXEC},
		{sandbox.ViolationKindNetworkConnect, controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_NETWORK_CONNECT},
		{sandbox.ViolationKindNetworkBind, controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_NETWORK_BIND},
		{sandbox.ViolationKindGenericDeny, controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_GENERIC},
		{sandbox.ViolationKindEnvScrub, controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_UNSPECIFIED},
	}

	for _, tc := range tests {
		t.Run(string(tc.kind), func(t *testing.T) {
			assert.Equal(t, tc.want, mapSandboxViolationKind(tc.kind))
		})
	}
}

func TestMapSandboxDriver(t *testing.T) {
	tests := []struct {
		driver sandbox.DriverName
		want   controltowerv1.PmgSandboxDriver
	}{
		{sandbox.DriverSeatbelt, controltowerv1.PmgSandboxDriver_PMG_SANDBOX_DRIVER_SEATBELT},
		{sandbox.DriverLandlock, controltowerv1.PmgSandboxDriver_PMG_SANDBOX_DRIVER_LANDLOCK},
		{sandbox.DriverBubblewrap, controltowerv1.PmgSandboxDriver_PMG_SANDBOX_DRIVER_BUBBLEWRAP},
		{sandbox.DriverProxy, controltowerv1.PmgSandboxDriver_PMG_SANDBOX_DRIVER_UNSPECIFIED},
	}

	for _, tc := range tests {
		t.Run(string(tc.driver), func(t *testing.T) {
			assert.Equal(t, tc.want, mapSandboxDriver(tc.driver))
		})
	}
}

func TestTranslateError(t *testing.T) {
	event := AuditEvent{
		Type:    EventTypeError,
		Message: "something went wrong",
		Error:   errors.New("connection refused"),
	}

	results := testSink.translateToPmgEvents(event)
	require.Len(t, results, 1)
	result := results[0]

	assert.Equal(t, controltowerv1.PmgEventType_PMG_EVENT_TYPE_ERROR, result.GetEventType())
	require.True(t, result.HasError())

	pmgErr := result.GetError()
	assert.Equal(t, "*errors.errorString", pmgErr.GetErrorType())
	assert.Equal(t, "something went wrong", pmgErr.GetMessage())
}

func TestTranslateErrorNilError(t *testing.T) {
	event := AuditEvent{
		Type:    EventTypeError,
		Message: "unknown issue",
		Error:   nil,
	}

	results := testSink.translateToPmgEvents(event)
	require.Len(t, results, 1)
	result := results[0]

	pmgErr := result.GetError()
	assert.Equal(t, "", pmgErr.GetErrorType())
	assert.Equal(t, "unknown issue", pmgErr.GetMessage())
}

func TestTranslateCooldownBlocked(t *testing.T) {
	publishDate := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	event := AuditEvent{
		Type:           EventTypeDependencyCooldown,
		PackageVersion: testPackageVersion("new-pkg", "1.0.0", "npm"),
		PublishDate:    publishDate,
		CooldownDays:   30,
		DaysAgo:        6,
		DaysLeft:       24,
	}

	results := testSink.translateToPmgEvents(event)
	require.Len(t, results, 1)
	result := results[0]

	assert.Equal(t, controltowerv1.PmgEventType_PMG_EVENT_TYPE_PACKAGE_DECISION, result.GetEventType())
	require.True(t, result.HasPackageDecision())

	decision := result.GetPackageDecision()
	assert.Equal(t, controltowerv1.PmgPackageAction_PMG_PACKAGE_ACTION_COOLDOWN_BLOCKED, decision.GetAction())
	assert.NotNil(t, decision.GetPackageVersion())

	require.True(t, decision.HasCooldown())
	cooldown := decision.GetCooldown()
	assert.Equal(t, publishDate.Unix(), cooldown.GetPublishDate().AsTime().Unix())
	assert.Equal(t, uint32(30), cooldown.GetCooldownDays())
	assert.Equal(t, uint32(6), cooldown.GetDaysSincePublish())
	assert.Equal(t, uint32(24), cooldown.GetDaysRemaining())
}

func TestTranslateHostObservation(t *testing.T) {
	event := AuditEvent{
		Type:            EventTypeProxyHostObserved,
		HostObservation: HostObservation{Hostname: "evil.example.com", Method: "CONNECT"},
	}

	results := testSink.translateToPmgEvents(event)
	require.Len(t, results, 1)
	result := results[0]

	assert.Equal(t, controltowerv1.PmgEventType_PMG_EVENT_TYPE_HOST_OBSERVATION, result.GetEventType())
	require.True(t, result.HasHostObservation())

	obs := result.GetHostObservation()
	assert.Equal(t, "evil.example.com", obs.GetHostname())
	assert.Equal(t, "CONNECT", obs.GetMethod())
}

func TestTranslateUnsupportedEventReturnsEmpty(t *testing.T) {
	unsupported := []EventType{
		EventTypeDependencyResolved,
		EventTypeInstallStarted,
		EventTypeInstallAllowed,
		EventTypeInstallInsecureBypass,
	}

	for _, et := range unsupported {
		t.Run(string(et), func(t *testing.T) {
			results := testSink.translateToPmgEvents(AuditEvent{Type: et})
			assert.Empty(t, results)
		})
	}
}

func TestMapPackageManager(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected controltowerv1.PmgPackageManager
	}{
		{"npm", "npm", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_NPM},
		{"npx", "npx", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_NPM},
		{"pnpm", "pnpm", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_PNPM},
		{"pnpx", "pnpx", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_PNPM},
		{"yarn", "yarn", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_YARN},
		{"bun", "bun", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_BUN},
		{"pip", "pip", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_PIP},
		{"pip3", "pip3", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_PIP},
		{"pipx", "pipx", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_PIP},
		{"poetry", "poetry", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_POETRY},
		{"uv", "uv", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_UV},
		{"uvx", "uvx", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_UV},
		{"unknown", "cargo", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_UNSPECIFIED},
		{"aube", "aube", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_AUBE},
		{"aubr", "aubr", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_AUBE},
		{"aubx", "aubx", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_AUBE},
		{"empty", "", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_UNSPECIFIED},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, mapPackageManager(tc.input))
		})
	}
}

func TestMapKubernetesWorkloadKind(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected controltowerv1.EndpointKubernetesWorkloadKind
	}{
		{"deployment", "Deployment", controltowerv1.EndpointKubernetesWorkloadKind_ENDPOINT_KUBERNETES_WORKLOAD_KIND_DEPLOYMENT},
		{"daemonset", "DaemonSet", controltowerv1.EndpointKubernetesWorkloadKind_ENDPOINT_KUBERNETES_WORKLOAD_KIND_DAEMON_SET},
		{"statefulset", "StatefulSet", controltowerv1.EndpointKubernetesWorkloadKind_ENDPOINT_KUBERNETES_WORKLOAD_KIND_STATEFUL_SET},
		{"job", "Job", controltowerv1.EndpointKubernetesWorkloadKind_ENDPOINT_KUBERNETES_WORKLOAD_KIND_JOB},
		{"cronjob", "CronJob", controltowerv1.EndpointKubernetesWorkloadKind_ENDPOINT_KUBERNETES_WORKLOAD_KIND_CRON_JOB},
		{"replicaset", "ReplicaSet", controltowerv1.EndpointKubernetesWorkloadKind_ENDPOINT_KUBERNETES_WORKLOAD_KIND_REPLICA_SET},
		{"pod", "Pod", controltowerv1.EndpointKubernetesWorkloadKind_ENDPOINT_KUBERNETES_WORKLOAD_KIND_POD},
		{"empty", "", controltowerv1.EndpointKubernetesWorkloadKind_ENDPOINT_KUBERNETES_WORKLOAD_KIND_UNSPECIFIED},
		{"crd falls through", "Rollout", controltowerv1.EndpointKubernetesWorkloadKind_ENDPOINT_KUBERNETES_WORKLOAD_KIND_UNSPECIFIED},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, mapKubernetesWorkloadKind(tc.input))
		})
	}
}

func TestTranslateSessionComplete(t *testing.T) {
	event := AuditEvent{
		Type: EventTypeSessionComplete,
		SessionData: &SessionData{
			PackageManager:       "npm",
			FlowType:             FlowTypeProxy,
			Outcome:              OutcomeSuccess,
			TotalAnalyzed:        10,
			AllowedCount:         8,
			BlockedCount:         1,
			ConfirmedCount:       1,
			TrustedSkipped:       2,
			InsecureBypassed:     0,
			CooldownBlockedCount: 3,
			Duration:             5 * time.Second,
			SandboxEnabled:       true,
			ParanoidMode:         false,
		},
	}

	results := testSink.translateToPmgEvents(event)
	require.Len(t, results, 1)

	summary := results[0].GetSessionSummary()
	require.NotNil(t, summary)
	assert.Equal(t, controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_NPM, summary.GetPackageManager())
	assert.Equal(t, controltowerv1.PmgFlowType_PMG_FLOW_TYPE_PROXY, summary.GetFlowType())
	assert.Equal(t, uint32(10), summary.GetTotalAnalyzed())
	assert.Equal(t, uint32(8), summary.GetAllowedCount())
	assert.Equal(t, uint32(1), summary.GetBlockedCount())
	assert.Equal(t, uint32(1), summary.GetConfirmedCount())
	assert.Equal(t, uint32(2), summary.GetTrustedSkipped())
	assert.Equal(t, uint32(3), summary.GetCooldownBlockedCount())
	assert.True(t, summary.GetSandboxEnabled())
	assert.False(t, summary.GetParanoidMode())
	assert.Equal(t, controltowerv1.PmgSessionOutcome_PMG_SESSION_OUTCOME_SUCCESS, summary.GetOutcome())
}

func TestTranslateSessionErrorInfo(t *testing.T) {
	zero := uint32(0)
	code42 := uint32(42)
	code130 := uint32(130)
	tests := []struct {
		name       string
		info       *runerror.Info
		wantSource controltowerv1.PmgErrorSource
		wantReason controltowerv1.PmgErrorReason
		wantCode   *uint32
	}{
		{name: "absent"},
		{
			name: "PMG setup failure",
			info: &runerror.Info{
				Source: runerror.SourcePMG, Reason: runerror.ReasonProxySetupFailed,
				Message: "listen tcp 127.0.0.1:3000: address already in use",
			},
			wantSource: controltowerv1.PmgErrorSource_PMG_ERROR_SOURCE_PMG,
			wantReason: controltowerv1.PmgErrorReason_PMG_ERROR_REASON_PROXY_SETUP_FAILED,
		},
		{
			name: "child exit",
			info: &runerror.Info{
				Source: runerror.SourceChildProcess, Reason: runerror.ReasonProcessExited,
				ExitCode: &code42,
			},
			wantSource: controltowerv1.PmgErrorSource_PMG_ERROR_SOURCE_CHILD_PROCESS,
			wantReason: controltowerv1.PmgErrorReason_PMG_ERROR_REASON_PROCESS_EXITED,
			wantCode:   &code42,
		},
		{
			name: "signal exit",
			info: &runerror.Info{
				Source: runerror.SourceChildProcess, Reason: runerror.ReasonProcessSignaled,
				ExitCode: &code130,
			},
			wantSource: controltowerv1.PmgErrorSource_PMG_ERROR_SOURCE_CHILD_PROCESS,
			wantReason: controltowerv1.PmgErrorReason_PMG_ERROR_REASON_PROCESS_SIGNALED,
			wantCode:   &code130,
		},
		{
			name: "present zero",
			info: &runerror.Info{
				Source: runerror.SourceChildProcess, Reason: runerror.ReasonProcessExited,
				ExitCode: &zero,
			},
			wantSource: controltowerv1.PmgErrorSource_PMG_ERROR_SOURCE_CHILD_PROCESS,
			wantReason: controltowerv1.PmgErrorReason_PMG_ERROR_REASON_PROCESS_EXITED,
			wantCode:   &zero,
		},
		{
			name:       "explicit unspecified",
			info:       &runerror.Info{},
			wantSource: controltowerv1.PmgErrorSource_PMG_ERROR_SOURCE_UNSPECIFIED,
			wantReason: controltowerv1.PmgErrorReason_PMG_ERROR_REASON_UNSPECIFIED,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := newSessionSummaryEvent(&SessionData{
				PackageManager: "npm",
				Outcome:        OutcomeError,
				ErrorInfo:      tt.info,
			})
			summary := event.GetSessionSummary()
			require.NotNil(t, summary)

			if tt.info == nil {
				assert.False(t, summary.HasErrorInfo())
				return
			}

			require.True(t, summary.HasErrorInfo())
			got := summary.GetErrorInfo()
			assert.Equal(t, tt.wantSource, got.GetSource())
			assert.Equal(t, tt.wantReason, got.GetReason())
			assert.Equal(t, tt.info.Message, got.GetMessage())
			if tt.wantCode == nil {
				assert.False(t, got.HasExitCode())
			} else {
				require.True(t, got.HasExitCode())
				assert.Equal(t, *tt.wantCode, got.GetExitCode())
			}
		})
	}
}

func TestMapUnknownErrorInfoValuesToUnspecified(t *testing.T) {
	got := mapErrorInfo(&runerror.Info{
		Source: runerror.Source(100), Reason: runerror.Reason(100), Message: "future value",
	})

	require.NotNil(t, got)
	assert.Equal(t, controltowerv1.PmgErrorSource_PMG_ERROR_SOURCE_UNSPECIFIED, got.GetSource())
	assert.Equal(t, controltowerv1.PmgErrorReason_PMG_ERROR_REASON_UNSPECIFIED, got.GetReason())
}

func TestTranslateSessionCompleteWithInsecureBypass(t *testing.T) {
	event := AuditEvent{
		Type: EventTypeSessionComplete,
		SessionData: &SessionData{
			PackageManager:   "pip",
			FlowType:         FlowTypeProxy,
			Outcome:          OutcomeInsecureBypass,
			InsecureBypassed: 3,
		},
	}

	results := testSink.translateToPmgEvents(event)
	require.Len(t, results, 2)

	assert.Equal(t, controltowerv1.PmgEventType_PMG_EVENT_TYPE_SESSION_SUMMARY, results[0].GetEventType())

	assert.Equal(t, controltowerv1.PmgEventType_PMG_EVENT_TYPE_INSECURE_BYPASS, results[1].GetEventType())
	bypass := results[1].GetInsecureBypass()
	require.NotNil(t, bypass)
	assert.Equal(t, controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_PIP, bypass.GetPackageManager())
	assert.Equal(t, uint32(3), bypass.GetPackagesBypassed())
}

func TestTranslateSessionCompleteNilSessionData(t *testing.T) {
	event := AuditEvent{
		Type:        EventTypeSessionComplete,
		SessionData: nil,
	}

	results := testSink.translateToPmgEvents(event)
	assert.Empty(t, results)
}

func TestMapFlowType(t *testing.T) {
	tests := []struct {
		name     string
		input    FlowType
		expected controltowerv1.PmgFlowType
	}{
		{"proxy", FlowTypeProxy, controltowerv1.PmgFlowType_PMG_FLOW_TYPE_PROXY},
		{"legacy guard maps to unspecified", FlowType("guard"), controltowerv1.PmgFlowType_PMG_FLOW_TYPE_UNSPECIFIED},
		{"unknown", FlowType("other"), controltowerv1.PmgFlowType_PMG_FLOW_TYPE_UNSPECIFIED},
		{"empty", FlowType(""), controltowerv1.PmgFlowType_PMG_FLOW_TYPE_UNSPECIFIED},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, mapFlowType(tc.input))
		})
	}
}

func TestMapSessionOutcome(t *testing.T) {
	tests := []struct {
		name     string
		input    Outcome
		expected controltowerv1.PmgSessionOutcome
	}{
		{"success", OutcomeSuccess, controltowerv1.PmgSessionOutcome_PMG_SESSION_OUTCOME_SUCCESS},
		{"blocked", OutcomeBlocked, controltowerv1.PmgSessionOutcome_PMG_SESSION_OUTCOME_BLOCKED},
		{"user_cancelled", OutcomeUserCancelled, controltowerv1.PmgSessionOutcome_PMG_SESSION_OUTCOME_USER_CANCELLED},
		{"error", OutcomeError, controltowerv1.PmgSessionOutcome_PMG_SESSION_OUTCOME_ERROR},
		{"dry_run", OutcomeDryRun, controltowerv1.PmgSessionOutcome_PMG_SESSION_OUTCOME_DRY_RUN},
		{"insecure_bypass", OutcomeInsecureBypass, controltowerv1.PmgSessionOutcome_PMG_SESSION_OUTCOME_INSECURE_BYPASS},
		{"unknown", Outcome("other"), controltowerv1.PmgSessionOutcome_PMG_SESSION_OUTCOME_UNSPECIFIED},
		{"empty", Outcome(""), controltowerv1.PmgSessionOutcome_PMG_SESSION_OUTCOME_UNSPECIFIED},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, mapSessionOutcome(tc.input))
		})
	}
}

func TestTranslateHostObservationDetails(t *testing.T) {
	cases := map[string]struct {
		seen  HostObservation
		check func(t *testing.T, obs *controltowerv1.PmgHostObservation)
	}{
		"a container carries its address": {
			seen: HostObservation{Hostname: "cdn.example.com", Method: "CONNECT", Port: 443, EntryPoint: ProxyEntryPointRedirectedNamespace, Client: ProxyClient{Address: "172.17.0.2"}},
			check: func(t *testing.T, obs *controltowerv1.PmgHostObservation) {
				assert.True(t, obs.HasPort())
				assert.Equal(t, uint32(443), obs.GetPort())
				assert.Equal(t, controltowerv1.PmgProxyEntryPoint_PMG_PROXY_ENTRY_POINT_REDIRECTED_NAMESPACE, obs.GetEntryPoint())
				require.True(t, obs.HasClient())
				assert.Equal(t, "172.17.0.2", obs.GetClient().GetAddress())
				assert.False(t, obs.GetClient().HasPid(), "a container names no process")
				assert.False(t, obs.GetClient().HasComm())
				assert.False(t, obs.GetClient().HasExecutable())
			},
		},
		"a host process carries its identity": {
			seen: HostObservation{Hostname: "cdn.example.com", Method: "CONNECT", EntryPoint: ProxyEntryPointRedirectedHost, Client: ProxyClient{PID: 42, Comm: "curl", Exe: "/usr/bin/curl"}},
			check: func(t *testing.T, obs *controltowerv1.PmgHostObservation) {
				require.True(t, obs.HasClient())
				assert.Equal(t, uint32(42), obs.GetClient().GetPid())
				assert.Equal(t, "curl", obs.GetClient().GetComm())
				assert.Equal(t, "/usr/bin/curl", obs.GetClient().GetExecutable())
				assert.False(t, obs.GetClient().HasAddress())
			},
		},
		"a process outside the PID namespace has a comm and no pid": {
			seen: HostObservation{Hostname: "cdn.example.com", Method: "CONNECT", EntryPoint: ProxyEntryPointRedirectedHost, Client: ProxyClient{Comm: "curl"}},
			check: func(t *testing.T, obs *controltowerv1.PmgHostObservation) {
				require.True(t, obs.HasClient())
				assert.False(t, obs.GetClient().HasPid())
				assert.Equal(t, "curl", obs.GetClient().GetComm())
			},
		},
		"nothing known stays unset": {
			seen: HostObservation{Hostname: "cdn.example.com", Method: "GET"},
			check: func(t *testing.T, obs *controltowerv1.PmgHostObservation) {
				assert.False(t, obs.HasPort(), "an unknown port is unset, not zero")
				assert.Equal(t, controltowerv1.PmgProxyEntryPoint_PMG_PROXY_ENTRY_POINT_UNSPECIFIED, obs.GetEntryPoint())
				assert.False(t, obs.HasClient())
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			results := testSink.translateToPmgEvents(AuditEvent{Type: EventTypeProxyHostObserved, HostObservation: tc.seen})
			require.Len(t, results, 1)
			obs := results[0].GetHostObservation()
			require.NotNil(t, obs)
			assert.Equal(t, tc.seen.Hostname, obs.GetHostname())
			assert.Equal(t, tc.seen.Method, obs.GetMethod())
			tc.check(t, obs)
		})
	}
}

func TestTranslateNetworkPolicy(t *testing.T) {
	sink := &cloudSink{}
	events := sink.translateToPmgEvents(AuditEvent{
		Type: EventTypeNetworkPolicy,
		NetworkDecision: NetworkDecision{
			Hostname:   "evil.example",
			Port:       443,
			Rule:       "*:*",
			Enforced:   true,
			EntryPoint: ProxyEntryPointRedirectedHost,
			Client:     ProxyClient{PID: 42, Comm: "curl", Exe: "/usr/bin/curl"},
		},
	})
	require.Len(t, events, 1)

	e := events[0]
	assert.Equal(t, controltowerv1.PmgEventType_PMG_EVENT_TYPE_NETWORK_POLICY_DECISION, e.GetEventType())
	d := e.GetNetworkPolicyDecision()
	require.NotNil(t, d)
	assert.Equal(t, "evil.example", d.GetHostname())
	assert.Equal(t, uint32(443), d.GetPort())
	assert.Equal(t, "*:*", d.GetRule())
	assert.Equal(t, controltowerv1.PmgNetworkPolicyAction_PMG_NETWORK_POLICY_ACTION_DENIED, d.GetAction())
	assert.Equal(t, controltowerv1.PmgNetworkPolicyMode_PMG_NETWORK_POLICY_MODE_ENFORCE, d.GetMode())
	assert.Equal(t, controltowerv1.PmgNetworkPolicySource_PMG_NETWORK_POLICY_SOURCE_RULE, d.GetSource())
	assert.Equal(t, controltowerv1.PmgNetworkPolicyException_PMG_NETWORK_POLICY_EXCEPTION_NONE, d.GetException())
	assert.Equal(t, controltowerv1.PmgProxyEntryPoint_PMG_PROXY_ENTRY_POINT_REDIRECTED_HOST, d.GetEntryPoint())
	assert.Equal(t, "/usr/bin/curl", d.GetClient().GetExecutable())

	observed := sink.translateToPmgEvents(AuditEvent{
		Type:            EventTypeNetworkPolicy,
		NetworkDecision: NetworkDecision{Hostname: "evil.example", Port: 80, Rule: "*:80"},
	})
	require.Len(t, observed, 1)
	assert.Equal(t, controltowerv1.PmgNetworkPolicyAction_PMG_NETWORK_POLICY_ACTION_OBSERVED, observed[0].GetNetworkPolicyDecision().GetAction())
	assert.Equal(t, controltowerv1.PmgNetworkPolicyMode_PMG_NETWORK_POLICY_MODE_AUDIT, observed[0].GetNetworkPolicyDecision().GetMode())
	assert.Nil(t, observed[0].GetNetworkPolicyDecision().GetClient())
}

func TestNetworkDecisionDetails(t *testing.T) {
	details := NetworkDecision{Hostname: "evil.example", Port: 443, Rule: "*:*", Enforced: false}.details()
	assert.Equal(t, "observed", details["action"])
	assert.Equal(t, "audit", details["mode"])
	assert.Equal(t, "*:*", details["rule"])
	assert.Equal(t, uint16(443), details["port"])
	assert.NotContains(t, details, "method")
}
