package audit

import (
	"fmt"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

func (s *cloudSink) translateToPmgEvents(event AuditEvent) []*controltowerv1.PmgEvent {
	switch event.Type {
	case EventTypeMalwareBlocked:
		return []*controltowerv1.PmgEvent{newPackageDecisionEvent(event, controltowerv1.PmgPackageAction_PMG_PACKAGE_ACTION_BLOCKED)}
	case EventTypeMalwareConfirmed:
		return []*controltowerv1.PmgEvent{newPackageDecisionEvent(event, controltowerv1.PmgPackageAction_PMG_PACKAGE_ACTION_CONFIRMED)}
	case EventTypeInstallInsecureBypass:
		// PmgInsecureBypass is a session-level aggregate (package manager + total bypassed count),
		// not a per-package event. It is emitted as part of EventTypeSessionComplete when
		// the session's insecureBypassed counter is > 0.
		return nil
	case EventTypeSandboxOverride:
		return []*controltowerv1.PmgEvent{newSandboxOverrideEvent(event)}
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

	var flattened []string
	for _, m := range event.Overrides {
		for k, v := range m {
			flattened = append(flattened, fmt.Sprintf("%s:%s", k, v))
		}
	}
	override.SetOverrides(flattened)

	e := &controltowerv1.PmgEvent{}
	e.SetEventType(controltowerv1.PmgEventType_PMG_EVENT_TYPE_SANDBOX_OVERRIDE)
	e.SetSandboxOverride(override)
	return e
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

func newSessionSummaryEvent(data *SessionData) *controltowerv1.PmgEvent {
	summary := &controltowerv1.PmgSessionSummary{}
	summary.SetPackageManager(mapPackageManager(data.PackageManager))
	summary.SetFlowType(mapFlowType(data.FlowType))
	summary.SetTotalAnalyzed(data.TotalAnalyzed)
	summary.SetAllowedCount(data.AllowedCount)
	summary.SetBlockedCount(data.BlockedCount)
	summary.SetConfirmedCount(data.ConfirmedCount)
	summary.SetTrustedSkipped(data.TrustedSkipped)
	summary.SetDuration(durationpb.New(data.Duration))
	summary.SetSandboxEnabled(data.SandboxEnabled)
	summary.SetParanoidMode(data.ParanoidMode)
	summary.SetTransitiveEnabled(data.TransitiveEnabled)
	summary.SetOutcome(mapSessionOutcome(data.Outcome))

	e := &controltowerv1.PmgEvent{}
	e.SetEventType(controltowerv1.PmgEventType_PMG_EVENT_TYPE_SESSION_SUMMARY)
	e.SetSessionSummary(summary)
	return e
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
	case FlowTypeGuard:
		return controltowerv1.PmgFlowType_PMG_FLOW_TYPE_GUARD
	case FlowTypeProxy:
		return controltowerv1.PmgFlowType_PMG_FLOW_TYPE_PROXY
	default:
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
	case "npm":
		return controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_NPM
	case "pnpm":
		return controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_PNPM
	case "yarn":
		return controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_YARN
	case "bun":
		return controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_BUN
	case "pip", "pip3":
		return controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_PIP
	case "poetry":
		return controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_POETRY
	case "uv":
		return controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_UV
	default:
		return controltowerv1.PmgPackageManager_PMG_PACKAGE_MANAGER_UNSPECIFIED
	}
}
