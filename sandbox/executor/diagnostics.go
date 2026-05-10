package executor

import (
	"fmt"
	"os"
	"path/filepath"
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
	first := primarySandboxViolation(report)
	if first == nil {
		return "Reason: sandbox denied an operation"
	}

	hint := fmt.Sprintf("Reason: %s", first.RuleLabel)

	if override := suggestSandboxOverride(*first); override != "" {
		hint = fmt.Sprintf("%s. Override: %s", hint, override)
	}

	return hint
}

func buildSandboxDetails(report *sandbox.ViolationReport) string {
	first := primarySandboxViolation(report)
	if first == nil {
		return ""
	}

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
	case sandbox.ViolationKindFSRead:
		return fmt.Sprintf("--sandbox-allow read=%s", v.Target)
	case sandbox.ViolationKindFSWrite, sandbox.ViolationKindFSDeleteOrRename:
		return fmt.Sprintf("--sandbox-allow write=%s", v.Target)
	case sandbox.ViolationKindExec:
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

func primarySandboxViolation(report *sandbox.ViolationReport) *sandbox.Violation {
	if report == nil || len(report.Violations) == 0 {
		return nil
	}

	cwd, _ := os.Getwd()
	bestIdx := 0
	bestScore := scoreSandboxViolation(report.Violations[0], cwd)

	for i := 1; i < len(report.Violations); i++ {
		score := scoreSandboxViolation(report.Violations[i], cwd)
		if score > bestScore || (score == bestScore && i > bestIdx) {
			bestIdx = i
			bestScore = score
		}
	}

	return &report.Violations[bestIdx]
}

func scoreSandboxViolation(v sandbox.Violation, cwd string) int {
	score := 0

	switch v.Kind {
	case sandbox.ViolationKindFSRead, sandbox.ViolationKindFSWrite:
		score += 120
	case sandbox.ViolationKindExec:
		score += 110
	case sandbox.ViolationKindFSDeleteOrRename:
		score += 100
	case sandbox.ViolationKindGenericDeny:
		score += 10
	default:
		score += 30
	}

	if isSafeSandboxOverrideTarget(v.Target) {
		score += 40
	}

	if v.Target != "" && v.Target != v.RuleTarget {
		score += 20
	}

	if isProjectPath(v.Target, cwd) {
		score += 80
	}

	if isSensitiveProjectFile(v.Target) {
		score += 60
	}

	if isNoisySystemPath(v.Target) {
		score -= 120
	}

	if v.Kind == sandbox.ViolationKindGenericDeny && v.Target == "" {
		score -= 40
	}

	return score
}

func isProjectPath(target, cwd string) bool {
	if target == "" || cwd == "" {
		return false
	}

	if strings.HasPrefix(target, ".") {
		return true
	}

	cleanTarget := filepath.Clean(target)
	cleanCwd := filepath.Clean(cwd)

	return cleanTarget == cleanCwd || strings.HasPrefix(cleanTarget, cleanCwd+string(filepath.Separator))
}

func isSensitiveProjectFile(target string) bool {
	if target == "" {
		return false
	}

	base := filepath.Base(target)
	switch {
	case strings.HasPrefix(base, ".env"):
		return true
	case base == ".npmrc", base == ".pypirc", base == ".netrc":
		return true
	case base == ".aws", base == ".ssh", base == ".kube", base == ".gnupg":
		return true
	default:
		return strings.Contains(target, string(filepath.Separator)+".ssh") ||
			strings.Contains(target, string(filepath.Separator)+".aws") ||
			strings.Contains(target, string(filepath.Separator)+".kube")
	}
}

func isNoisySystemPath(target string) bool {
	switch target {
	case "/dev/dtracehelper":
		return true
	default:
		return false
	}
}
