package audit

import (
	"fmt"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
)

func (s *cloudSink) translateToPmgEvent(event AuditEvent) *controltowerv1.PmgEvent {
	switch event.Type {
	case EventTypeMalwareBlocked:
		return newPackageDecisionEvent(event, controltowerv1.PmgPackageAction_PMG_PACKAGE_ACTION_BLOCKED)
	case EventTypeMalwareConfirmed:
		return newPackageDecisionEvent(event, controltowerv1.PmgPackageAction_PMG_PACKAGE_ACTION_CONFIRMED)
	case EventTypeInstallInsecureBypass:
		return newInsecureBypassEvent(event)
	case EventTypeSandboxOverride:
		return newSandboxOverrideEvent(event)
	case EventTypeError:
		return newErrorEvent(event)
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
	if event.IsMalware {
		decision.SetIsMalware(event.IsMalware)
	}
	if event.IsVerified {
		decision.SetIsVerified(event.IsVerified)
	}

	e := &controltowerv1.PmgEvent{}
	e.SetEventType(controltowerv1.PmgEventType_PMG_EVENT_TYPE_PACKAGE_DECISION)
	e.SetPackageDecision(decision)
	return e
}

func newInsecureBypassEvent(event AuditEvent) *controltowerv1.PmgEvent {
	bypass := &controltowerv1.PmgInsecureBypass{}
	bypass.SetPackageManager(mapPackageManager(event.PackageManager))
	bypass.SetPackagesBypassed(uint32(event.PackageCount))

	e := &controltowerv1.PmgEvent{}
	e.SetEventType(controltowerv1.PmgEventType_PMG_EVENT_TYPE_INSECURE_BYPASS)
	e.SetInsecureBypass(bypass)
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
