package audit

import (
	"context"
	"fmt"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/analytics"
)

var global *auditor

func setGlobal(a *auditor) {
	global = a
}

func resetGlobal() {
	global = nil
}

// Initialize sets up the audit system with an eventlog sink and, when enabled,
// a cloud sync sink.
func Initialize(cfg *config.RuntimeConfig) error {
	var sinks []Sink
	sinks = append(sinks, newEventlogSink())

	if cfg.Config.Cloud.Enabled && !analytics.IsDisabled() {
		cs, err := newCloudSink(cfg)
		if err != nil {
			return fmt.Errorf("cloud sync is enabled but failed to initialize: %w", err)
		}
		sinks = append(sinks, cs)
	}

	if cfg.Config.Cloud.Enabled && analytics.IsDisabled() {
		log.Warnf("Cloud sync is disabled because telemetry is disabled")
	}

	setGlobal(newAuditor(sinks...))
	return nil
}

func Close() error {
	if global == nil {
		return nil
	}
	return global.close()
}

func logEvent(event AuditEvent) {
	if global == nil {
		return
	}
	global.dispatch(context.Background(), event)
}

func pkgName(pv *packagev1.PackageVersion) string {
	if pv != nil {
		if pkg := pv.GetPackage(); pkg != nil {
			return pkg.GetName()
		}
	}
	return ""
}

func pkgVersion(pv *packagev1.PackageVersion) string {
	if pv != nil {
		return pv.GetVersion()
	}
	return ""
}

func pkgEcosystem(pv *packagev1.PackageVersion) string {
	if pv != nil {
		if pkg := pv.GetPackage(); pkg != nil {
			return pkg.GetEcosystem().String()
		}
	}
	return ""
}

// LogMalwareBlocked records that a package was blocked due to malware detection.
func LogMalwareBlocked(pv *packagev1.PackageVersion, reason, analysisID, referenceURL string, isMalware, isVerified bool) {
	logEvent(AuditEvent{
		Type:           EventTypeMalwareBlocked,
		Message:        fmt.Sprintf("Blocked installation of malicious package: %s@%s", pkgName(pv), pkgVersion(pv)),
		PackageVersion: pv,
		AnalysisID:     analysisID,
		IsMalware:      isMalware,
		IsVerified:     isVerified,
		Details: map[string]interface{}{
			"reason":        reason,
			"analysis_id":   analysisID,
			"reference_url": referenceURL,
		},
	})

	if global != nil {
		global.recordBlocked()
	}
}

// LogMalwareConfirmed records that the user confirmed installation of a flagged package.
func LogMalwareConfirmed(pv *packagev1.PackageVersion, analysisID string, isMalware, isVerified bool) {
	logEvent(AuditEvent{
		Type:           EventTypeMalwareConfirmed,
		Message:        fmt.Sprintf("User confirmed installation of flagged package: %s@%s", pkgName(pv), pkgVersion(pv)),
		PackageVersion: pv,
		AnalysisID:     analysisID,
		IsMalware:      isMalware,
		IsVerified:     isVerified,
	})

	if global != nil {
		global.recordConfirmed()
	}
}

// LogInstallAllowed records that a package passed security checks and installation was permitted.
func LogInstallAllowed(pv *packagev1.PackageVersion, packageCount int) {
	logEvent(AuditEvent{
		Type:           EventTypeInstallAllowed,
		Message:        fmt.Sprintf("Installation allowed for %s@%s (%d packages analyzed)", pkgName(pv), pkgVersion(pv), packageCount),
		PackageVersion: pv,
		Details: map[string]interface{}{
			"packages_analyzed": packageCount,
		},
		PackageCount: packageCount,
	})

	if global != nil {
		global.recordAllowed()
	}
}

// LogInstallTrustedAllowed records that a trusted package skipped security analysis.
func LogInstallTrustedAllowed(pv *packagev1.PackageVersion) {
	logEvent(AuditEvent{
		Type:           EventTypeInstallTrustedAllowed,
		Message:        fmt.Sprintf("Installation allowed for trusted package: %s@%s", pkgName(pv), pkgVersion(pv)),
		PackageVersion: pv,
	})

	if global != nil {
		global.recordTrustedSkipped()
	}
}

// LogInstallInsecureBypass records that a package bypassed security analysis due to insecure mode.
func LogInstallInsecureBypass(pv *packagev1.PackageVersion) {
	logEvent(AuditEvent{
		Type:           EventTypeInstallInsecureBypass,
		Message:        fmt.Sprintf("Installation bypassed analysis due to insecure installation mode: %s@%s", pkgName(pv), pkgVersion(pv)),
		PackageVersion: pv,
	})

	if global != nil {
		global.recordInsecureBypassed()
	}
}

// LogInstallStarted records the start of a package installation session.
func LogInstallStarted(packageManager string, args []string) {
	logEvent(AuditEvent{
		Type:    EventTypeInstallStarted,
		Message: fmt.Sprintf("Starting package installation with %s", packageManager),
		Details: map[string]interface{}{
			"package_manager": packageManager,
			"arguments":       args,
		},
		PackageManager: packageManager,
		Args:           args,
	})

	if global != nil {
		global.startSession(packageManager, args)
	}
}

// LogProxyHostObserved records an outbound host observed by the proxy that is not a known registry.
func LogProxyHostObserved(hostname, method, reason string, details map[string]interface{}) {
	base := map[string]interface{}{
		"hostname": hostname,
		"method":   method,
		"reason":   reason,
	}

	logEvent(AuditEvent{
		Type:     EventTypeProxyHostObserved,
		Message:  fmt.Sprintf("Proxy observed outbound host: %s", hostname),
		Details:  mergeDetails(base, details),
		Hostname: hostname,
		Method:   method,
		Reason:   reason,
	})
}

// LogSandboxOverride records that runtime sandbox policy overrides were applied.
func LogSandboxOverride(sandboxProfile string, overrides []map[string]string) {
	logEvent(AuditEvent{
		Type:    EventTypeSandboxOverride,
		Message: fmt.Sprintf("Sandbox runtime overrides applied (%d rules)", len(overrides)),
		Details: map[string]interface{}{
			"sandbox_profile":           sandboxProfile,
			"sandbox_runtime_overrides": overrides,
		},
		ProfileName: sandboxProfile,
		Overrides:   overrides,
	})
}

// LogError records a significant error during PMG operation.
func LogError(message string, err error) {
	event := AuditEvent{
		Type:    EventTypeError,
		Message: message,
		Error:   err,
	}

	if err != nil {
		event.Details = map[string]interface{}{
			"error": err.Error(),
		}
	}

	logEvent(event)
}

func mergeDetails(base, extra map[string]interface{}) map[string]interface{} {
	if base == nil {
		base = make(map[string]interface{})
	}
	for k, v := range extra {
		base[k] = v
	}
	return base
}
