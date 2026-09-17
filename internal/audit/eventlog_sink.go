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
		EventType:   string(event.Type),
		Message:     event.Message,
		PackageName: pkgName(event.PackageVersion),
		Version:     pkgVersion(event.PackageVersion),
		Ecosystem:   pkgEcosystem(event.PackageVersion),
		Details:     details,
	}
	return eventlog.LogEvent(elEvent)
}

func sessionDataToDetails(sd *SessionData) map[string]interface{} {
	details := map[string]interface{}{
		"outcome":                sd.Outcome,
		"flow_type":              sd.FlowType,
		"package_manager":        sd.PackageManager,
		"total_analyzed":         sd.TotalAnalyzed,
		"allowed_count":          sd.AllowedCount,
		"blocked_count":          sd.BlockedCount,
		"confirmed_count":        sd.ConfirmedCount,
		"trusted_skipped":        sd.TrustedSkipped,
		"insecure_bypassed":      sd.InsecureBypassed,
		"cooldown_blocked_count": sd.CooldownBlockedCount,
	}
	if sd.ErrorInfo != nil {
		errorInfo := map[string]interface{}{
			"source":  sd.ErrorInfo.Source.String(),
			"reason":  sd.ErrorInfo.Reason.String(),
			"message": sd.ErrorInfo.Message,
		}
		if sd.ErrorInfo.ExitCode != nil {
			errorInfo["exit_code"] = *sd.ErrorInfo.ExitCode
		}
		details["error_info"] = errorInfo
	}
	return details
}

func (s *eventlogSink) Close() error {
	return nil
}
