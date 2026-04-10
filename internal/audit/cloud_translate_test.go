package audit

import (
	"errors"
	"testing"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCloudSink returns a cloudSink with no real SyncClient, suitable for testing translation.
var testSink = &cloudSink{invocationID: "test-invocation"}

func TestTranslateMalwareBlocked(t *testing.T) {
	event := AuditEvent{
		Type:           EventTypeMalwareBlocked,
		PackageVersion: testPackageVersion("evil-pkg", "1.2.3", "npm"),
		AnalysisID:     "analysis-123",
		IsMalware:      true,
		IsVerified:     true,
	}

	result := testSink.translateToPmgEvent(event)
	require.NotNil(t, result)

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

	result := testSink.translateToPmgEvent(event)
	require.NotNil(t, result)

	assert.Equal(t, controltowerv1.PmgEventType_PMG_EVENT_TYPE_PACKAGE_DECISION, result.GetEventType())
	require.True(t, result.HasPackageDecision())

	decision := result.GetPackageDecision()
	assert.Equal(t, controltowerv1.PmgPackageAction_PMG_PACKAGE_ACTION_CONFIRMED, decision.GetAction())
	assert.Equal(t, "analysis-456", decision.GetAnalysisId())
	assert.False(t, decision.GetIsMalware())
	assert.False(t, decision.GetIsVerified())
}

func TestTranslateInsecureBypass(t *testing.T) {
	event := AuditEvent{
		Type:           EventTypeInstallInsecureBypass,
		PackageManager: "npm",
		PackageCount:   5,
	}

	result := testSink.translateToPmgEvent(event)
	require.NotNil(t, result)

	assert.Equal(t, controltowerv1.PmgEventType_PMG_EVENT_TYPE_INSECURE_BYPASS, result.GetEventType())
	require.True(t, result.HasInsecureBypass())

	bypass := result.GetInsecureBypass()
	assert.Equal(t, controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_NPM, bypass.GetPackageManager())
	assert.Equal(t, uint32(5), bypass.GetPackagesBypassed())
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

	result := testSink.translateToPmgEvent(event)
	require.NotNil(t, result)

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

	result := testSink.translateToPmgEvent(event)
	require.NotNil(t, result)

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

	result := testSink.translateToPmgEvent(event)
	require.NotNil(t, result)

	pmgErr := result.GetError()
	assert.Equal(t, "", pmgErr.GetErrorType())
	assert.Equal(t, "unknown issue", pmgErr.GetMessage())
}

func TestTranslateUnsupportedEventReturnsNil(t *testing.T) {
	unsupported := []EventType{
		EventTypeProxyHostObserved,
		EventTypeDependencyResolved,
		EventTypeInstallStarted,
		EventTypeInstallAllowed,
		EventTypeInstallTrustedAllowed,
	}

	for _, et := range unsupported {
		t.Run(string(et), func(t *testing.T) {
			result := testSink.translateToPmgEvent(AuditEvent{Type: et})
			assert.Nil(t, result)
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
		{"pnpm", "pnpm", controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_PNPM},
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
