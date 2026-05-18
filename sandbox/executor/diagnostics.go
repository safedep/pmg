package executor

import (
	"fmt"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/usefulerror"
)

// WrapCommandExecutionError converts a package manager execution error into a
// user-facing error. It never attributes the failure to the sandbox: causation
// cannot be inferred from EPERM/EACCES returns alone, and a security tool
// should not make best-effort claims. Any observed sandbox denials are
// persisted to the violation cache for forensic review via
// `pmg sandbox violations list` and `pmg sandbox explain`.
func WrapCommandExecutionError(err error, result *sandbox.ExecutionResult, exitCode int) error {
	if err == nil {
		return nil
	}

	observed := observeAndPersistViolations(result, err)

	humanError := "Failed to execute package manager command"
	if exitCode >= 0 {
		humanError = fmt.Sprintf("Package manager command exited with code: %d", exitCode)
	}

	help := "Check the package manager command and its arguments"
	builder := usefulerror.Useful().
		WithCode(usefulerror.ErrCodePackageManagerExecutionFailed).
		WithHumanError(humanError).
		WithHelp(help)

	if observed > 0 {
		builder = builder.WithAdditionalHelp(fmt.Sprintf(
			"Sandbox observed %d denied operation(s) during this run. Run `pmg sandbox violations list` to investigate.",
			observed,
		))
	}

	return builder.Wrap(err)
}

// observeAndPersistViolations collects any sandbox violation report associated
// with the run and writes it to the violation cache. Returns the number of
// violations observed. Failures are logged and swallowed; observability MUST
// NOT affect command exit.
func observeAndPersistViolations(result *sandbox.ExecutionResult, runErr error) int {
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
