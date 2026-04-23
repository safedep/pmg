package audit

import (
	"testing"

	"github.com/safedep/pmg/internal/eventlog"
	"github.com/stretchr/testify/assert"
)

func TestEventlogSinkTranslatesAllEventTypes(t *testing.T) {
	tests := []struct {
		name     string
		input    EventType
		expected eventlog.EventType
	}{
		{"malware_blocked", EventTypeMalwareBlocked, eventlog.EventTypeMalwareBlocked},
		{"malware_confirmed", EventTypeMalwareConfirmed, eventlog.EventTypeMalwareConfirmed},
		{"install_allowed", EventTypeInstallAllowed, eventlog.EventTypeInstallAllowed},
		{"install_trusted_allowed", EventTypeInstallTrustedAllowed, eventlog.EventTypeInstallTrustedAllowed},
		{"install_started", EventTypeInstallStarted, eventlog.EventTypeInstallStarted},
		{"dependency_resolved", EventTypeDependencyResolved, eventlog.EventTypeDependencyResolved},
		{"install_insecure_bypass", EventTypeInstallInsecureBypass, eventlog.EventTypeInstallInsecureBypass},
		{"proxy_host_observed", EventTypeProxyHostObserved, eventlog.EventTypeProxyHostObserved},
		{"sandbox_override", EventTypeSandboxOverride, eventlog.EventTypeSandboxOverride},
		{"error", EventTypeError, eventlog.EventTypeError},
		{"session_complete", EventTypeSessionComplete, eventlog.EventType("session_complete")},
		{"unknown_type", EventType("custom_event"), eventlog.EventType("custom_event")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapEventType(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
