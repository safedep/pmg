package audit

import (
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

type EventType string

const (
	EventTypeMalwareBlocked        EventType = "malware_blocked"
	EventTypeMalwareConfirmed      EventType = "malware_confirmed"
	EventTypeInstallAllowed        EventType = "install_allowed"
	EventTypeInstallTrustedAllowed EventType = "install_trusted_allowed"
	EventTypeInstallStarted        EventType = "install_started"
	EventTypeDependencyResolved    EventType = "dependency_resolved"
	EventTypeInstallInsecureBypass EventType = "install_insecure_bypass"
	EventTypeProxyHostObserved     EventType = "proxy_host_observed"
	EventTypeSandboxOverride       EventType = "sandbox_override"
	EventTypeError                 EventType = "error"
	EventTypeSessionComplete       EventType = "session_complete"
)

// AuditEvent is the canonical audit event for PMG. It carries all data any
// sink might need. Fields are zero-valued when not applicable to the event type.
type AuditEvent struct {
	Type      EventType
	Timestamp time.Time
	Message   string

	// Typed package version — populated for package-level events.
	PackageVersion *packagev1.PackageVersion

	// Analysis context
	AnalysisID string
	IsMalware  bool
	IsVerified bool

	// Freeform details for backward-compatible eventlog output.
	Details map[string]interface{}

	// Install context
	PackageManager string
	Args           []string
	PackageCount   int

	// Sandbox context
	ProfileName string
	Overrides   []map[string]string

	// Proxy context
	Hostname string
	Method   string
	Reason   string

	// Error context
	Error error
}
