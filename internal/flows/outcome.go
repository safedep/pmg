package flows

import "github.com/safedep/pmg/internal/ui"

// inferOutcome determines the execution outcome based on configuration and execution data.
// This function is shared across different flow implementations (guard-based, proxy-based)
// to maintain consistent outcome logic without coupling flows to each other.
//
// Outcome precedence:
//  1. Error (if no packages were blocked)
//  2. Insecure installation bypass
//  3. Dry run mode
//  4. User cancellation
//  5. Packages blocked
//  6. Success (default)
func inferOutcome(insecureMode, dryRun bool, blockedCount, userCancelledCount int, err error) ui.ExecutionOutcome {
	// Error takes precedence unless we have blocked packages
	if err != nil && blockedCount == 0 {
		return ui.OutcomeError
	}

	// Config-based outcomes
	if insecureMode {
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
