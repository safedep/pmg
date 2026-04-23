package audit

import (
	"context"

	"github.com/safedep/pmg/internal/eventlog"
)

type eventlogSink struct{}

func newEventlogSink() *eventlogSink {
	return &eventlogSink{}
}

func (s *eventlogSink) Handle(_ context.Context, event AuditEvent) error {
	details := event.Details
	if details == nil && event.SessionData != nil {
		details = sessionDataToDetails(event.SessionData)
	}

	elEvent := eventlog.Event{
		Timestamp:   event.Timestamp,
		EventType:   mapEventType(event.Type),
		Message:     event.Message,
		PackageName: pkgName(event.PackageVersion),
		Version:     pkgVersion(event.PackageVersion),
		Ecosystem:   pkgEcosystem(event.PackageVersion),
		Details:     details,
	}
	return eventlog.LogEvent(elEvent)
}

func sessionDataToDetails(sd *SessionData) map[string]interface{} {
	return map[string]interface{}{
		"outcome":           sd.Outcome,
		"flow_type":         sd.FlowType,
		"package_manager":   sd.PackageManager,
		"total_analyzed":    sd.TotalAnalyzed,
		"allowed_count":     sd.AllowedCount,
		"blocked_count":     sd.BlockedCount,
		"confirmed_count":   sd.ConfirmedCount,
		"trusted_skipped":   sd.TrustedSkipped,
		"insecure_bypassed": sd.InsecureBypassed,
	}
}

func (s *eventlogSink) Close() error {
	return nil
}

func mapEventType(t EventType) eventlog.EventType {
	switch t {
	case EventTypeMalwareBlocked:
		return eventlog.EventTypeMalwareBlocked
	case EventTypeMalwareConfirmed:
		return eventlog.EventTypeMalwareConfirmed
	case EventTypeInstallAllowed:
		return eventlog.EventTypeInstallAllowed
	case EventTypeInstallTrustedAllowed:
		return eventlog.EventTypeInstallTrustedAllowed
	case EventTypeInstallStarted:
		return eventlog.EventTypeInstallStarted
	case EventTypeDependencyResolved:
		return eventlog.EventTypeDependencyResolved
	case EventTypeInstallInsecureBypass:
		return eventlog.EventTypeInstallInsecureBypass
	case EventTypeProxyHostObserved:
		return eventlog.EventTypeProxyHostObserved
	case EventTypeSandboxOverride:
		return eventlog.EventTypeSandboxOverride
	case EventTypeError:
		return eventlog.EventTypeError
	case EventTypeSessionComplete:
		return eventlog.EventType("session_complete")
	default:
		return eventlog.EventType(string(t))
	}
}
