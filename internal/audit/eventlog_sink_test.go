package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
