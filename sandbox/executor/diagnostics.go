package executor

import (
	"slices"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/sandbox"
)

// ObserveViolations collects any sandbox violation report associated with the
// run, folds in the environment scrubs recorded by the executor, persists the
// result to the violation cache for forensic review (via
// `pmg sandbox violations list` / `pmg sandbox explain`), records the denials
// in the audit log, and returns the number of violations recorded. Failures
// are logged and swallowed. Observability MUST NOT affect command exit.
//
// Call it after every run, once the result holds the exit error. A program
// can catch a denial and exit 0, so a clean run can still carry a denial.
//
// This is the sandbox package's only stake in command-failure handling. It
// deliberately does not classify or shape the failure: causation cannot be
// inferred from EPERM/EACCES returns alone, so attribution is left to the
// execution layer (see internal/runner classify).
func ObserveViolations(result *sandbox.ExecutionResult) int {
	if result == nil {
		return 0
	}
	runErr := result.ExitError()

	report, diagErr := result.BestEffortViolation()
	if diagErr != nil {
		// Env scrubs come from the executor, not the driver, so a failed
		// collection must not discard them.
		log.Warnf("failed to collect sandbox diagnostics: %v", diagErr)
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
	report.CleanExit = runErr == nil

	persistViolationReport(report)
	if denials, ok := auditReport(report); ok {
		audit.LogSandboxViolations(denials)
	}
	return len(report.Violations)
}

type denialKey struct {
	kind    sandbox.ViolationKind
	target  string
	process string
}

func denialKeyOf(v sandbox.Violation) denialKey {
	return denialKey{kind: v.Kind, target: v.Target, process: v.Process}
}

// auditReport groups the denials of report into distinct entries with a
// count, the most relevant first. A driver can report one denial thousands
// of times in a retry loop. Env scrubs are not denials, and noise is a
// denial that ordinary tools cause on almost every run, so both stay out.
// It reports false when no denial is left.
func auditReport(report *sandbox.ViolationReport) (audit.SandboxViolationReport, bool) {
	// The primary of an explanation is the last of the denials with the top
	// score. Each distinct denial takes the place of its last occurrence, so
	// the first ranked entry is that primary.
	var distinct []sandbox.Violation
	counts := make(map[denialKey]int)
	for _, v := range slices.Backward(report.Violations) {
		if v.Kind == sandbox.ViolationKindEnvScrub || sandbox.IsNoise(report.SandboxName, v) {
			continue
		}

		key := denialKeyOf(v)
		if counts[key] == 0 {
			distinct = append(distinct, v)
		}
		counts[key] += max(v.Hits, 1)
	}
	if len(distinct) == 0 {
		return audit.SandboxViolationReport{}, false
	}
	slices.Reverse(distinct)

	sandbox.RankViolations(report.SandboxName, distinct)

	out := audit.SandboxViolationReport{
		Driver:     report.SandboxName,
		Profile:    report.PolicyName,
		CleanExit:  report.CleanExit,
		Violations: make([]audit.SandboxViolation, 0, len(distinct)),
	}
	for _, v := range distinct {
		// An entry with no usable target keeps its kind and count for the
		// local log. The cloud translation drops it.
		target, _ := v.SplitTarget()
		out.Violations = append(out.Violations, audit.SandboxViolation{
			Kind:       v.Kind,
			Path:       target.Path,
			Executable: target.Executable,
			Host:       target.Host,
			Port:       target.Port,
			Rule:       v.RuleTarget,
			Process:    v.Process,
			Count:      counts[denialKeyOf(v)],
		})
	}

	return out, true
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
