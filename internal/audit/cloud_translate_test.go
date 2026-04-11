package audit

import (
	"errors"
	"testing"
	"time"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCloudSink returns a cloudSink with no real SyncClient, suitable for testing translation.
var testSink = &cloudSink{SyncClientBundle: &SyncClientBundle{}, invocationID: "test-invocation"}

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
			{"read": "/tmp"},
			{"write": "/var/log"},
		},
	}

	results := testSink.translateToPmgEvents(event)
	require.Len(t, results, 1)
	result := results[0]

	assert.Equal(t, controltowerv1.PmgEventType_PMG_EVENT_TYPE_SANDBOX_OVERRIDE, result.GetEventType())
	require.True(t, result.HasSandboxOverride())

	override := result.GetSandboxOverride()
	assert.Equal(t, "strict", override.GetSandboxProfile())
	assert.ElementsMatch(t, []string{"read:/tmp", "write:/var/log"}, override.GetOverrides())
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

func TestTranslateUnsupportedEventReturnsEmpty(t *testing.T) {
	unsupported := []EventType{
		EventTypeProxyHostObserved,
		EventTypeDependencyResolved,
		EventTypeInstallStarted,
		EventTypeInstallAllowed,
		EventTypeInstallTrustedAllowed,
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
		{"poetry", "poetry", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_POETRY},
		{"uv", "uv", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_UV},
		{"unknown", "cargo", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_UNSPECIFIED},
		{"empty", "", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_UNSPECIFIED},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, mapPackageManager(tc.input))
		})
	}
}

func TestTranslateSessionComplete(t *testing.T) {
	event := AuditEvent{
		Type: EventTypeSessionComplete,
		SessionData: &SessionData{
			PackageManager:    "npm",
			FlowType:          FlowTypeProxy,
			Outcome:           OutcomeSuccess,
			TotalAnalyzed:     10,
			AllowedCount:      8,
			BlockedCount:      1,
			ConfirmedCount:    1,
			TrustedSkipped:    2,
			InsecureBypassed:  0,
			Duration:          5 * time.Second,
			SandboxEnabled:    true,
			ParanoidMode:      false,
			TransitiveEnabled: true,
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
	assert.True(t, summary.GetSandboxEnabled())
	assert.False(t, summary.GetParanoidMode())
	assert.True(t, summary.GetTransitiveEnabled())
	assert.Equal(t, controltowerv1.PmgSessionOutcome_PMG_SESSION_OUTCOME_SUCCESS, summary.GetOutcome())
}

func TestTranslateSessionCompleteWithInsecureBypass(t *testing.T) {
	event := AuditEvent{
		Type: EventTypeSessionComplete,
		SessionData: &SessionData{
			PackageManager:   "pip",
			FlowType:         FlowTypeGuard,
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
		{"guard", FlowTypeGuard, controltowerv1.PmgFlowType_PMG_FLOW_TYPE_GUARD},
		{"proxy", FlowTypeProxy, controltowerv1.PmgFlowType_PMG_FLOW_TYPE_PROXY},
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
