package executor

import (
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/sandbox"
)

// ObserveViolations collects any sandbox violation report associated with the
// run, folds in the environment scrubs recorded by the executor, persists the
// result to the violation cache for forensic review (via
// `pmg sandbox violations list` / `pmg sandbox explain`), and returns the number
// of violations recorded. Failures are logged and swallowed; observability MUST
// NOT affect command exit.
//
// Call it after every run, with runErr nil for a clean exit. A program can
// catch a denial and exit 0, so a clean run can still carry a denial.
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
		// Env scrubs come from the executor, not the driver, so a failed
		// collection must not discard them. A clean run gets a debug line,
		// because a broken platform log would otherwise warn on every run.
		logf := log.Warnf
		if runErr == nil {
			logf = log.Debugf
		}
		logf("failed to collect sandbox diagnostics: %v", diagErr)
		report = nil
	}

	// A clean run records a report only when the driver saw a denial. Most
	// runs scrub an environment variable, and a scrub-only record for each
	// clean run would push the denials out of the cache.
	if runErr == nil && (report == nil || len(report.Violations) == 0) {
		return 0
	}

	report = sandbox.MergeEnvScrub(report, result.EnvScrub())
	if report == nil || len(report.Violations) == 0 {
		return 0
	}

	persistViolationReport(report)
	return len(report.Violations)
}

// ObserveNetworkDenials records the connections the proxy refused under
// the network policy as violations, so `pmg sandbox explain --last` and
// `pmg sandbox allow net-connect=<host>:<port>` work on them.
func ObserveNetworkDenials(policyName string, denials []sandbox.Violation) {
	if len(denials) == 0 {
		return
	}

	persistViolationReport(&sandbox.ViolationReport{
		SandboxName: sandbox.DriverProxy,
		PolicyName:  policyName,
		Violations:  denials,
	})
}

func persistViolationReport(report *sandbox.ViolationReport) {
	cfg := config.Get()
	if cfg == nil || cfg.SandboxViolationCacheDir() == "" {
		return
	}

	if _, err := sandbox.NewViolationCache(cfg.SandboxViolationCacheDir()).Write(report); err != nil {
		log.Warnf("failed to persist sandbox violation report: %v", err)
	}
}
