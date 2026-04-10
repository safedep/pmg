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
	elEvent := eventlog.Event{
		Timestamp:   event.Timestamp,
		EventType:   mapEventType(event.Type),
		Message:     event.Message,
		PackageName: pkgName(event.PackageVersion),
		Version:     pkgVersion(event.PackageVersion),
		Ecosystem:   pkgEcosystem(event.PackageVersion),
		Details:     event.Details,
	}
	return eventlog.LogEvent(elEvent)
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
