package executor

import (
	"fmt"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/usefulerror"
)

// WrapCommandExecutionError converts a package manager execution error into a
// user-facing error. When sandbox diagnostics are available, they take
// precedence over the generic exit-code-only message.
func WrapCommandExecutionError(err error, result *sandbox.ExecutionResult, exitCode int) error {
	if err == nil {
		return nil
	}

	if result != nil {
		report, diagErr := result.BestEffortViolation(err)
		if diagErr != nil {
			log.Warnf("failed to collect sandbox diagnostics: %v", diagErr)
		} else if report != nil && len(report.Violations) > 0 {
			return usefulerror.Useful().
				WithCode(usefulerror.ErrCodeSandboxViolation).
				WithHumanError("PMG sandbox blocked this command").
				WithHelp(buildSandboxHint(report)).
				WithAdditionalHelp(buildSandboxDetails(report)).
				Wrap(err)
		}
	}

	humanError := "Failed to execute package manager command"
	if exitCode >= 0 {
		humanError = fmt.Sprintf("Package manager command exited with code: %d", exitCode)
	}

	return usefulerror.Useful().
		WithCode(usefulerror.ErrCodePackageManagerExecutionFailed).
		WithHumanError(humanError).
		WithHelp("Check the package manager command and its arguments").
		Wrap(err)
}

func buildSandboxHint(report *sandbox.ViolationReport) string {
	first := report.Violations[0]

	hint := fmt.Sprintf("Reason: %s", first.RuleLabel)

	if override := suggestSandboxOverride(first); override != "" {
		hint = fmt.Sprintf("%s. Override: %s", hint, override)
	}

	return hint
}

func buildSandboxDetails(report *sandbox.ViolationReport) string {
	first := report.Violations[0]

	lines := []string{
		fmt.Sprintf("Sandbox: %s", report.SandboxName),
		fmt.Sprintf("Policy: %s", report.PolicyName),
		fmt.Sprintf("Correlation: %s", report.CorrelationID),
		fmt.Sprintf("Process: %s", emptyFallback(first.Process, "unknown")),
		fmt.Sprintf("Violation: %s", first.RuleLabel),
	}

	if first.RuleTarget != "" && first.RuleTarget != first.Target {
		lines = append(lines, fmt.Sprintf("Matched rule: %s", first.RuleTarget))
	}

	if first.RawLog != "" {
		lines = append(lines, fmt.Sprintf("Seatbelt log: %s", first.RawLog))
	}

	if len(report.Violations) > 1 {
		lines = append(lines, fmt.Sprintf("Additional denials observed: %d", len(report.Violations)-1))
	}

	return strings.Join(lines, "\n")
}

func suggestSandboxOverride(v sandbox.Violation) string {
	if !isSafeSandboxOverrideTarget(v.Target) {
		return ""
	}

	switch v.Kind {
	case "file-read":
		return fmt.Sprintf("--sandbox-allow read=%s", v.Target)
	case "file-write", "file-write-unlink":
		return fmt.Sprintf("--sandbox-allow write=%s", v.Target)
	case "process-exec":
		return fmt.Sprintf("--sandbox-allow exec=%s", v.Target)
	default:
		return ""
	}
}

func isSafeSandboxOverrideTarget(value string) bool {
	if value == "" {
		return false
	}

	return !strings.ContainsAny(value, "*?[]")
}

func emptyFallback(value, fallback string) string {
	if value == "" {
		return fallback
	}

	return value
}
