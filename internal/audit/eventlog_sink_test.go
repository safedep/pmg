package audit

import (
	"testing"

	"github.com/safedep/pmg/internal/runerror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEventTypeOnDiskValues pins the event_type strings written to the on-disk
// event log. The audit package is the single owner of this vocabulary; the
// eventlog sink writes string(event.Type) verbatim, so these values are the
// file-format contract and must not change without a migration.
func TestEventTypeOnDiskValues(t *testing.T) {
	tests := []struct {
		input    EventType
		expected string
	}{
		{EventTypeMalwareBlocked, "malware_blocked"},
		{EventTypeMalwareConfirmed, "malware_confirmed"},
		{EventTypeInstallAllowed, "install_allowed"},
		{EventTypeInstallTrustedAllowed, "install_trusted_allowed"},
		{EventTypeInstallStarted, "install_started"},
		{EventTypeDependencyResolved, "dependency_resolved"},
		{EventTypeInstallInsecureBypass, "install_insecure_bypass"},
		{EventTypeProxyHostObserved, "proxy_host_observed"},
		{EventTypeDependencyCooldown, "dependency_cooldown"},
		{EventTypeCooldownSkipped, "dependency_cooldown_skipped"},
		{EventTypeSandboxOverride, "sandbox_override"},
		{EventTypeError, "error"},
		{EventTypeSessionComplete, "session_complete"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.input))
		})
	}
}

func TestSessionDataDetailsIncludesErrorInfo(t *testing.T) {
	exitCode := uint32(42)
	details := sessionDataToDetails(&SessionData{ErrorInfo: &runerror.Info{
		Source:   runerror.SourceChildProcess,
		Reason:   runerror.ReasonProcessExited,
		ExitCode: &exitCode,
	}})

	errorInfo, ok := details["error_info"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "child_process", errorInfo["source"])
	assert.Equal(t, "process_exited", errorInfo["reason"])
	assert.NotContains(t, errorInfo, "message")
	assert.Equal(t, uint32(42), errorInfo["exit_code"])
}

func TestSessionDataDetailsOmitsAbsentExitCode(t *testing.T) {
	details := sessionDataToDetails(&SessionData{ErrorInfo: &runerror.Info{
		Source:  runerror.SourcePMG,
		Reason:  runerror.ReasonProxySetupFailed,
		Message: "listen tcp 127.0.0.1:3000: address already in use",
	}})

	errorInfo, ok := details["error_info"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "listen tcp 127.0.0.1:3000: address already in use", errorInfo["message"])
	assert.NotContains(t, errorInfo, "exit_code")
}

func TestSessionDataDetailsOmitsAbsentErrorInfo(t *testing.T) {
	details := sessionDataToDetails(&SessionData{})

	assert.NotContains(t, details, "error_info")
}
