package flows

import (
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/ui"
)

func auditOutcome(outcome ui.ExecutionOutcome) audit.Outcome {
	switch outcome {
	case ui.OutcomeSuccess:
		return audit.OutcomeSuccess
	case ui.OutcomeBlocked:
		return audit.OutcomeBlocked
	case ui.OutcomeUserCancelled:
		return audit.OutcomeUserCancelled
	case ui.OutcomeDryRun:
		return audit.OutcomeDryRun
	case ui.OutcomeError:
		return audit.OutcomeError
	case ui.OutcomeInsecureBypass:
		return audit.OutcomeInsecureBypass
	default:
		return audit.OutcomeError
	}
}

// InferOutcome determines the execution outcome based on configuration and execution data.
//
// Outcome precedence:
//  1. Error (if no packages were blocked)
//  2. Insecure installation bypass (if no packages were blocked)
//  3. Dry run mode
//  4. User cancellation
//  5. Packages blocked
//  6. Success (default)
//
// Insecure mode skips the malware analysis, but a package rule and the
// dependency cooldown still block. A blocked run must report the block, so
// the bypass outcome applies only when nothing was blocked.
func InferOutcome(insecureMode, dryRun bool, blockedCount, userCancelledCount int, err error) ui.ExecutionOutcome {
	// Error takes precedence unless we have blocked packages
	if err != nil && blockedCount == 0 {
		return ui.OutcomeError
	}

	// Config-based outcomes
	if insecureMode && blockedCount == 0 {
		return ui.OutcomeInsecureBypass
	}

	if dryRun {
		return ui.OutcomeDryRun
	}

	// User cancellation
	if userCancelledCount > 0 {
		return ui.OutcomeUserCancelled
	}

	// Blocked packages take precedence over errors
	if blockedCount > 0 {
		return ui.OutcomeBlocked
	}

	return ui.OutcomeSuccess
}
