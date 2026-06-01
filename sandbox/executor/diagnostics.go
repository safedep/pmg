package executor

import (
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/sandbox"
)

// ObserveViolations collects any sandbox violation report associated with the
// run, persists it to the violation cache for forensic review (via
// `pmg sandbox violations list` / `pmg sandbox explain`), and returns the number
// of violations observed. Failures are logged and swallowed; observability MUST
// NOT affect command exit.
//
// This is the sandbox package's only stake in command-failure handling. It
// deliberately does not classify or shape the failure: causation cannot be
// inferred from EPERM/EACCES returns alone, so attribution is left to the
// execution layer (see internal/runner classify).
func ObserveViolations(result *sandbox.ExecutionResult, runErr error) int {
	if result == nil {
		return 0
	}

	report, diagErr := result.BestEffortViolation(runErr)
	if diagErr != nil {
		log.Warnf("failed to collect sandbox diagnostics: %v", diagErr)
		return 0
	}
	if report == nil || len(report.Violations) == 0 {
		return 0
	}

	cfg := config.Get()
	if cfg == nil {
		return len(report.Violations)
	}

	dir := cfg.SandboxViolationCacheDir()
	if dir == "" {
		return len(report.Violations)
	}

	if _, err := sandbox.NewViolationCache(dir).Write(report); err != nil {
		log.Warnf("failed to persist sandbox violation report: %v", err)
	}

	return len(report.Violations)
}
