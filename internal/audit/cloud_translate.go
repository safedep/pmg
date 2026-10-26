package audit

import (
	"fmt"
	"strings"
	"unicode/utf8"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	"github.com/safedep/pmg/internal/runerror"
	"github.com/safedep/pmg/sandbox"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *cloudSink) translateToPmgEvents(event AuditEvent) []*controltowerv1.PmgEvent {
	switch event.Type {
	case EventTypeMalwareBlocked:
		return []*controltowerv1.PmgEvent{newPackageDecisionEvent(event, controltowerv1.PmgPackageAction_PMG_PACKAGE_ACTION_BLOCKED)}
	case EventTypeMalwareConfirmed:
		return []*controltowerv1.PmgEvent{newPackageDecisionEvent(event, controltowerv1.PmgPackageAction_PMG_PACKAGE_ACTION_CONFIRMED)}
	case EventTypeCooldownSkipped:
		return []*controltowerv1.PmgEvent{newPackageDecisionEvent(event, controltowerv1.PmgPackageAction_PMG_PACKAGE_ACTION_COOLDOWN_SKIPPED)}
	case EventTypeInstallTrustedAllowed:
		return []*controltowerv1.PmgEvent{newPackageDecisionEvent(event, controltowerv1.PmgPackageAction_PMG_PACKAGE_ACTION_TRUSTED)}
	case EventTypeInstallInsecureBypass:
		// PmgInsecureBypass is a session-level aggregate (package manager + total bypassed count),
		// not a per-package event. It is emitted as part of EventTypeSessionComplete when
		// the session's insecureBypassed counter is > 0.
		return nil
	case EventTypeDependencyCooldown:
		return []*controltowerv1.PmgEvent{newCooldownBlockedEvent(event)}
	case EventTypeNetworkPolicy:
		return []*controltowerv1.PmgEvent{newNetworkPolicyEvent(event)}
	case EventTypeProxyHostObserved:
		return []*controltowerv1.PmgEvent{newHostObservationEvent(event)}
	case EventTypeSandboxOverride:
		return []*controltowerv1.PmgEvent{newSandboxOverrideEvent(event)}
	case EventTypeSandboxViolation:
		if e := newSandboxViolationEvent(event.SandboxViolations); e != nil {
			return []*controltowerv1.PmgEvent{e}
		}
		return nil
	case EventTypeError:
		return []*controltowerv1.PmgEvent{newErrorEvent(event)}
	case EventTypeSessionComplete:
		if event.SessionData == nil {
			return nil
		}
		events := []*controltowerv1.PmgEvent{newSessionSummaryEvent(event.SessionData)}
		if event.SessionData.InsecureBypassed > 0 {
			events = append(events, newInsecureBypassFromSession(event.SessionData))
		}
		return events
	default:
		return nil
	}
}

func newPackageDecisionEvent(event AuditEvent, action controltowerv1.PmgPackageAction) *controltowerv1.PmgEvent {
	decision := &controltowerv1.PmgPackageDecision{}
	decision.SetPackageVersion(event.PackageVersion)
	decision.SetAction(action)

	if event.AnalysisID != "" {
		decision.SetAnalysisId(event.AnalysisID)
	}
	decision.SetIsMalware(event.IsMalware)
	decision.SetIsVerified(event.IsVerified)

	e := &controltowerv1.PmgEvent{}
	e.SetEventType(controltowerv1.PmgEventType_PMG_EVENT_TYPE_PACKAGE_DECISION)
	e.SetPackageDecision(decision)
	return e
}

func newSandboxOverrideEvent(event AuditEvent) *controltowerv1.PmgEvent {
	override := &controltowerv1.PmgSandboxOverride{}
	override.SetSandboxProfile(event.ProfileName)

	// One string per override, in the --sandbox-allow form, so the type and
	// the value of an override stay together.
	overrides := make([]string, 0, len(event.Overrides))
	for _, m := range event.Overrides {
		overrides = append(overrides, m["type"]+"="+m["value"])
	}
	override.SetOverrides(overrides)

	e := &controltowerv1.PmgEvent{}
	e.SetEventType(controltowerv1.PmgEventType_PMG_EVENT_TYPE_SANDBOX_OVERRIDE)
	e.SetSandboxOverride(override)
	return e
}

// The bounds of PmgSandboxViolationReport. Control Tower rejects the whole
// sync batch when one event breaks a bound, and the rejected batch stays at
// the head of the WAL, so the translation keeps every value inside them.
const (
	maxSandboxViolations       = 100
	maxSandboxViolationPath    = 4096
	maxSandboxViolationHost    = 253
	maxSandboxViolationRule    = 4096
	maxSandboxViolationProcess = 256
	maxSandboxProfile          = 256

	// sandboxViolationBudget bounds the strings of one event, so a full batch
	// of these events stays near 6 MiB.
	sandboxViolationBudget = 64 << 10
)

// newSandboxViolationEvent keeps the denials in their ranked order until a
// bound is reached. distinct_count still counts every denial. It returns nil
// when no entry fits, because a report holds at least one.
func newSandboxViolationEvent(r SandboxViolationReport) *controltowerv1.PmgEvent {
	var violations []*controltowerv1.PmgSandboxViolation
	budget := sandboxViolationBudget
	for _, v := range r.Violations {
		if len(violations) == maxSandboxViolations {
			break
		}

		violation, size, ok := newSandboxViolation(v)
		if !ok {
			continue
		}

		budget -= size
		if budget < 0 {
			break
		}
		violations = append(violations, violation)
	}
	if len(violations) == 0 {
		return nil
	}

	exitStatus := controltowerv1.PmgSandboxExitStatus_PMG_SANDBOX_EXIT_STATUS_FAILED
	if r.CleanExit {
		exitStatus = controltowerv1.PmgSandboxExitStatus_PMG_SANDBOX_EXIT_STATUS_SUCCESS
	}

	report := &controltowerv1.PmgSandboxViolationReport{}
	report.SetDriver(mapSandboxDriver(r.Driver))
	report.SetSandboxProfile(clipUTF8(r.Profile, maxSandboxProfile))
	report.SetExitStatus(exitStatus)
	report.SetViolations(violations)
	report.SetDistinctCount(uint32(len(r.Violations)))

	e := &controltowerv1.PmgEvent{}
	e.SetEventType(controltowerv1.PmgEventType_PMG_EVENT_TYPE_SANDBOX_VIOLATION)
	e.SetSandboxViolationReport(report)
	return e
}

// newSandboxViolation sets exactly one of path, executable and host, as the
// proto requires, and reports the bytes of its strings. It reports false for
// an entry with no target or a target over its bound. A target is dropped
// and not cut, because a cut path names another file.
func newSandboxViolation(v SandboxViolation) (*controltowerv1.PmgSandboxViolation, int, bool) {
	violation := &controltowerv1.PmgSandboxViolation{}
	violation.SetKind(mapSandboxViolationKind(v.Kind))

	var target string
	var bound int
	switch {
	case v.Path != "" && v.Executable == "" && v.Host == "":
		target, bound = validUTF8(v.Path), maxSandboxViolationPath
		violation.SetPath(target)
	case v.Executable != "" && v.Path == "" && v.Host == "":
		target, bound = validUTF8(v.Executable), maxSandboxViolationPath
		violation.SetExecutable(target)
	case v.Host != "" && v.Path == "" && v.Executable == "":
		target, bound = validUTF8(v.Host), maxSandboxViolationHost
		violation.SetHost(target)
		if v.Port != nil {
			violation.SetPort(uint32(*v.Port))
		}
	default:
		return nil, 0, false
	}
	if len(target) > bound {
		return nil, 0, false
	}

	rule := clipUTF8(v.Rule, maxSandboxViolationRule)
	if rule != "" {
		violation.SetRule(rule)
	}
	process := clipUTF8(v.Process, maxSandboxViolationProcess)
	if process != "" {
		violation.SetProcess(process)
	}
	violation.SetCount(uint32(max(v.Count, 1)))

	return violation, len(target) + len(rule) + len(process), true
}

// validUTF8 replaces the invalid bytes of s. A proto string must be valid
// UTF-8, and a Linux path can hold any byte.
func validUTF8(s string) string {
	return strings.ToValidUTF8(s, string(utf8.RuneError))
}

// clipUTF8 makes s valid UTF-8 and cuts it to at most n bytes. A bound counts
// characters, so n bytes is always inside it.
func clipUTF8(s string, n int) string {
	s = validUTF8(s)
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

func mapSandboxDriver(driver sandbox.DriverName) controltowerv1.PmgSandboxDriver {
	switch driver {
	case sandbox.DriverSeatbelt:
		return controltowerv1.PmgSandboxDriver_PMG_SANDBOX_DRIVER_SEATBELT
	case sandbox.DriverLandlock:
		return controltowerv1.PmgSandboxDriver_PMG_SANDBOX_DRIVER_LANDLOCK
	case sandbox.DriverBubblewrap:
		return controltowerv1.PmgSandboxDriver_PMG_SANDBOX_DRIVER_BUBBLEWRAP
	default:
		return controltowerv1.PmgSandboxDriver_PMG_SANDBOX_DRIVER_UNSPECIFIED
	}
}

func mapSandboxViolationKind(kind sandbox.ViolationKind) controltowerv1.PmgSandboxViolationKind {
	switch kind {
	case sandbox.ViolationKindFSRead:
		return controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_FILESYSTEM_READ
	case sandbox.ViolationKindFSWrite:
		return controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_FILESYSTEM_WRITE
	case sandbox.ViolationKindFSDeleteOrRename:
		return controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_FILESYSTEM_DELETE_OR_RENAME
	case sandbox.ViolationKindExec:
		return controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_EXEC
	case sandbox.ViolationKindNetworkConnect:
		return controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_NETWORK_CONNECT
	case sandbox.ViolationKindNetworkBind:
		return controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_NETWORK_BIND
	case sandbox.ViolationKindGenericDeny:
		return controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_GENERIC
	default:
		return controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_UNSPECIFIED
	}
}

func newErrorEvent(event AuditEvent) *controltowerv1.PmgEvent {
	pmgErr := &controltowerv1.PmgError{}
	if event.Error != nil {
		pmgErr.SetErrorType(fmt.Sprintf("%T", event.Error))
	}
	pmgErr.SetMessage(event.Message)

	e := &controltowerv1.PmgEvent{}
	e.SetEventType(controltowerv1.PmgEventType_PMG_EVENT_TYPE_ERROR)
	e.SetError(pmgErr)
	return e
}

func newCooldownBlockedEvent(event AuditEvent) *controltowerv1.PmgEvent {
	decision := &controltowerv1.PmgPackageDecision{}
	decision.SetPackageVersion(event.PackageVersion)
	decision.SetAction(controltowerv1.PmgPackageAction_PMG_PACKAGE_ACTION_COOLDOWN_BLOCKED)

	cooldown := &controltowerv1.PmgDependencyCooldown{}
	if !event.PublishDate.IsZero() {
		cooldown.SetPublishDate(timestamppb.New(event.PublishDate))
	}
	cooldown.SetCooldownDays(uint32(event.CooldownDays))
	cooldown.SetDaysSincePublish(uint32(event.DaysAgo))
	cooldown.SetDaysRemaining(uint32(event.DaysLeft))
	decision.SetCooldown(cooldown)

	e := &controltowerv1.PmgEvent{}
	e.SetEventType(controltowerv1.PmgEventType_PMG_EVENT_TYPE_PACKAGE_DECISION)
	e.SetPackageDecision(decision)
	return e
}

func newHostObservationEvent(event AuditEvent) *controltowerv1.PmgEvent {
	seen := event.HostObservation
	obs := &controltowerv1.PmgHostObservation{}
	obs.SetHostname(seen.Hostname)
	obs.SetMethod(seen.Method)
	if seen.Port != 0 {
		obs.SetPort(uint32(seen.Port))
	}
	obs.SetEntryPoint(mapEntryPoint(seen.EntryPoint))
	if !seen.Client.IsZero() {
		obs.SetClient(newProxyClient(seen.Client))
	}

	e := &controltowerv1.PmgEvent{}
	e.SetEventType(controltowerv1.PmgEventType_PMG_EVENT_TYPE_HOST_OBSERVATION)
	e.SetHostObservation(obs)
	return e
}

func newNetworkPolicyEvent(event AuditEvent) *controltowerv1.PmgEvent {
	d := event.NetworkDecision
	decision := &controltowerv1.PmgNetworkPolicyDecision{}
	decision.SetHostname(d.Hostname)
	if d.Port != 0 {
		decision.SetPort(uint32(d.Port))
	}
	decision.SetSource(controltowerv1.PmgNetworkPolicySource_PMG_NETWORK_POLICY_SOURCE_RULE)
	decision.SetRule(d.Rule)
	decision.SetException(controltowerv1.PmgNetworkPolicyException_PMG_NETWORK_POLICY_EXCEPTION_NONE)
	if d.Enforced {
		decision.SetAction(controltowerv1.PmgNetworkPolicyAction_PMG_NETWORK_POLICY_ACTION_DENIED)
		decision.SetMode(controltowerv1.PmgNetworkPolicyMode_PMG_NETWORK_POLICY_MODE_ENFORCE)
	} else {
		decision.SetAction(controltowerv1.PmgNetworkPolicyAction_PMG_NETWORK_POLICY_ACTION_OBSERVED)
		decision.SetMode(controltowerv1.PmgNetworkPolicyMode_PMG_NETWORK_POLICY_MODE_AUDIT)
	}
	decision.SetEntryPoint(mapEntryPoint(d.EntryPoint))
	if !d.Client.IsZero() {
		decision.SetClient(newProxyClient(d.Client))
	}

	e := &controltowerv1.PmgEvent{}
	e.SetEventType(controltowerv1.PmgEventType_PMG_EVENT_TYPE_NETWORK_POLICY_DECISION)
	e.SetNetworkPolicyDecision(decision)
	return e
}

func newSessionSummaryEvent(data *SessionData) *controltowerv1.PmgEvent {
	summary := &controltowerv1.PmgSessionSummary{}
	summary.SetPackageManager(mapPackageManager(data.PackageManager))
	summary.SetFlowType(mapFlowType(data.FlowType))
	summary.SetTotalAnalyzed(data.TotalAnalyzed)
	summary.SetAllowedCount(data.AllowedCount)
	summary.SetBlockedCount(data.BlockedCount)
	summary.SetConfirmedCount(data.ConfirmedCount)
	summary.SetTrustedSkipped(data.TrustedSkipped)
	summary.SetCooldownBlockedCount(data.CooldownBlockedCount)
	summary.SetDuration(durationpb.New(data.Duration))
	summary.SetSandboxEnabled(data.SandboxEnabled)
	summary.SetParanoidMode(data.ParanoidMode)
	summary.SetOutcome(mapSessionOutcome(data.Outcome))
	if errorInfo := mapErrorInfo(data.ErrorInfo); errorInfo != nil {
		summary.SetErrorInfo(errorInfo)
	}

	e := &controltowerv1.PmgEvent{}
	e.SetEventType(controltowerv1.PmgEventType_PMG_EVENT_TYPE_SESSION_SUMMARY)
	e.SetSessionSummary(summary)
	return e
}

func mapErrorInfo(info *runerror.Info) *controltowerv1.PmgErrorInfo {
	if info == nil {
		return nil
	}

	result := &controltowerv1.PmgErrorInfo{}
	result.SetSource(mapErrorSource(info.Source))
	result.SetReason(mapErrorReason(info.Reason))
	if info.Message != "" {
		result.SetMessage(info.Message)
	}
	if info.ExitCode != nil {
		result.SetExitCode(*info.ExitCode)
	}
	return result
}

func mapErrorSource(source runerror.Source) controltowerv1.PmgErrorSource {
	switch source {
	case runerror.SourcePMG:
		return controltowerv1.PmgErrorSource_PMG_ERROR_SOURCE_PMG
	case runerror.SourceChildProcess:
		return controltowerv1.PmgErrorSource_PMG_ERROR_SOURCE_CHILD_PROCESS
	default:
		return controltowerv1.PmgErrorSource_PMG_ERROR_SOURCE_UNSPECIFIED
	}
}

func mapErrorReason(reason runerror.Reason) controltowerv1.PmgErrorReason {
	switch reason {
	case runerror.ReasonProcessExited:
		return controltowerv1.PmgErrorReason_PMG_ERROR_REASON_PROCESS_EXITED
	case runerror.ReasonProcessSignaled:
		return controltowerv1.PmgErrorReason_PMG_ERROR_REASON_PROCESS_SIGNALED
	case runerror.ReasonCommandParseFailed:
		return controltowerv1.PmgErrorReason_PMG_ERROR_REASON_COMMAND_PARSE_FAILED
	case runerror.ReasonConfigurationInvalid:
		return controltowerv1.PmgErrorReason_PMG_ERROR_REASON_CONFIGURATION_INVALID
	case runerror.ReasonEcosystemUnsupported:
		return controltowerv1.PmgErrorReason_PMG_ERROR_REASON_ECOSYSTEM_UNSUPPORTED
	case runerror.ReasonCertificateSetupFailed:
		return controltowerv1.PmgErrorReason_PMG_ERROR_REASON_CERTIFICATE_SETUP_FAILED
	case runerror.ReasonAnalyzerInitializationFailed:
		return controltowerv1.PmgErrorReason_PMG_ERROR_REASON_ANALYZER_INITIALIZATION_FAILED
	case runerror.ReasonProxySetupFailed:
		return controltowerv1.PmgErrorReason_PMG_ERROR_REASON_PROXY_SETUP_FAILED
	case runerror.ReasonExecutableNotFound:
		return controltowerv1.PmgErrorReason_PMG_ERROR_REASON_EXECUTABLE_NOT_FOUND
	case runerror.ReasonExecutableResolutionFailed:
		return controltowerv1.PmgErrorReason_PMG_ERROR_REASON_EXECUTABLE_RESOLUTION_FAILED
	case runerror.ReasonProcessLaunchFailed:
		return controltowerv1.PmgErrorReason_PMG_ERROR_REASON_PROCESS_LAUNCH_FAILED
	case runerror.ReasonExecutionSetupFailed:
		return controltowerv1.PmgErrorReason_PMG_ERROR_REASON_EXECUTION_SETUP_FAILED
	default:
		return controltowerv1.PmgErrorReason_PMG_ERROR_REASON_UNSPECIFIED
	}
}

func newInsecureBypassFromSession(data *SessionData) *controltowerv1.PmgEvent {
	bypass := &controltowerv1.PmgInsecureBypass{}
	bypass.SetPackageManager(mapPackageManager(data.PackageManager))
	bypass.SetPackagesBypassed(data.InsecureBypassed)

	e := &controltowerv1.PmgEvent{}
	e.SetEventType(controltowerv1.PmgEventType_PMG_EVENT_TYPE_INSECURE_BYPASS)
	e.SetInsecureBypass(bypass)
	return e
}

func mapFlowType(ft FlowType) controltowerv1.PmgFlowType {
	switch ft {
	case FlowTypeProxy:
		return controltowerv1.PmgFlowType_PMG_FLOW_TYPE_PROXY
	default:
		// Includes "guard" events recorded by pre-removal PMG versions that may
		// still be present in an unsynced local WAL.
		return controltowerv1.PmgFlowType_PMG_FLOW_TYPE_UNSPECIFIED
	}
}

func mapSessionOutcome(outcome Outcome) controltowerv1.PmgSessionOutcome {
	switch outcome {
	case OutcomeSuccess:
		return controltowerv1.PmgSessionOutcome_PMG_SESSION_OUTCOME_SUCCESS
	case OutcomeBlocked:
		return controltowerv1.PmgSessionOutcome_PMG_SESSION_OUTCOME_BLOCKED
	case OutcomeUserCancelled:
		return controltowerv1.PmgSessionOutcome_PMG_SESSION_OUTCOME_USER_CANCELLED
	case OutcomeError:
		return controltowerv1.PmgSessionOutcome_PMG_SESSION_OUTCOME_ERROR
	case OutcomeDryRun:
		return controltowerv1.PmgSessionOutcome_PMG_SESSION_OUTCOME_DRY_RUN
	case OutcomeInsecureBypass:
		return controltowerv1.PmgSessionOutcome_PMG_SESSION_OUTCOME_INSECURE_BYPASS
	default:
		return controltowerv1.PmgSessionOutcome_PMG_SESSION_OUTCOME_UNSPECIFIED
	}
}

func mapPackageManager(name string) controltowerv1.PmgPackageManager {
	switch name {
	case "npm", "npx":
		return controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_NPM
	case "pnpm", "pnpx":
		return controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_PNPM
	case "yarn":
		return controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_YARN
	case "bun":
		return controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_BUN
	case "pip", "pip3", "pipx":
		return controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_PIP
	case "poetry":
		return controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_POETRY
	case "uv", "uvx":
		return controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_UV
	case "aube", "aubr", "aubx":
		return controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_AUBE
	default:
		return controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_UNSPECIFIED
	}
}

// mapKubernetesWorkloadKind maps the platform-injected KUBE_WORKLOAD_KIND to
// the typed enum. PMG does not infer the kind, so a custom or CRD-based
// controller falls through to UNSPECIFIED.
func mapKubernetesWorkloadKind(kind string) controltowerv1.EndpointKubernetesWorkloadKind {
	switch kind {
	case "Deployment":
		return controltowerv1.EndpointKubernetesWorkloadKind_ENDPOINT_KUBERNETES_WORKLOAD_KIND_DEPLOYMENT
	case "DaemonSet":
		return controltowerv1.EndpointKubernetesWorkloadKind_ENDPOINT_KUBERNETES_WORKLOAD_KIND_DAEMON_SET
	case "StatefulSet":
		return controltowerv1.EndpointKubernetesWorkloadKind_ENDPOINT_KUBERNETES_WORKLOAD_KIND_STATEFUL_SET
	case "Job":
		return controltowerv1.EndpointKubernetesWorkloadKind_ENDPOINT_KUBERNETES_WORKLOAD_KIND_JOB
	case "CronJob":
		return controltowerv1.EndpointKubernetesWorkloadKind_ENDPOINT_KUBERNETES_WORKLOAD_KIND_CRON_JOB
	case "ReplicaSet":
		return controltowerv1.EndpointKubernetesWorkloadKind_ENDPOINT_KUBERNETES_WORKLOAD_KIND_REPLICA_SET
	case "Pod":
		return controltowerv1.EndpointKubernetesWorkloadKind_ENDPOINT_KUBERNETES_WORKLOAD_KIND_POD
	default:
		return controltowerv1.EndpointKubernetesWorkloadKind_ENDPOINT_KUBERNETES_WORKLOAD_KIND_UNSPECIFIED
	}
}

func mapEntryPoint(ep ProxyEntryPoint) controltowerv1.PmgProxyEntryPoint {
	switch ep {
	case ProxyEntryPointExplicit:
		return controltowerv1.PmgProxyEntryPoint_PMG_PROXY_ENTRY_POINT_EXPLICIT
	case ProxyEntryPointRedirectedHost:
		return controltowerv1.PmgProxyEntryPoint_PMG_PROXY_ENTRY_POINT_REDIRECTED_HOST
	case ProxyEntryPointRedirectedNamespace:
		return controltowerv1.PmgProxyEntryPoint_PMG_PROXY_ENTRY_POINT_REDIRECTED_NAMESPACE
	default:
		return controltowerv1.PmgProxyEntryPoint_PMG_PROXY_ENTRY_POINT_UNSPECIFIED
	}
}

// newProxyClient sets only the fields the proxy knew. The message fields
// have presence, so an unset field reads as unknown and not as zero.
// HostObservation.details writes the same fields for the event log.
func newProxyClient(c ProxyClient) *controltowerv1.PmgProxyClient {
	client := &controltowerv1.PmgProxyClient{}
	if c.PID != 0 {
		client.SetPid(c.PID)
	}
	if c.Comm != "" {
		client.SetComm(c.Comm)
	}
	if c.Exe != "" {
		client.SetExecutable(c.Exe)
	}
	if c.Address != "" {
		client.SetAddress(c.Address)
	}
	return client
}
