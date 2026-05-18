package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Explanation is structured, render-free explanation data for a violation
// report. The cmd layer formats this through internal/ui/.
type Explanation struct {
	Hint              string
	Details           string
	SuggestedOverride string
	Primary           *Violation
}

// BuildExplanation produces an Explanation for the given report.
func BuildExplanation(report *ViolationReport) Explanation {
	primary := primaryViolation(report)
	exp := Explanation{
		Hint:    explanationHint(primary),
		Details: explanationDetails(report, primary),
		Primary: primary,
	}
	if primary != nil {
		exp.SuggestedOverride = suggestOverride(*primary)
	}
	return exp
}

func explanationHint(primary *Violation) string {
	if primary == nil {
		return "Reason: sandbox denied an operation"
	}

	hint := fmt.Sprintf("Reason: %s", primary.RuleLabel)

	if override := suggestOverride(*primary); override != "" {
		hint = fmt.Sprintf("%s. Override: %s", hint, override)
	}

	return hint
}

func explanationDetails(report *ViolationReport, primary *Violation) string {
	if primary == nil {
		return ""
	}

	lines := []string{
		fmt.Sprintf("Sandbox: %s", report.SandboxName),
		fmt.Sprintf("Policy: %s", report.PolicyName),
		fmt.Sprintf("Correlation: %s", report.CorrelationID),
		fmt.Sprintf("Process: %s", emptyFallback(primary.Process, "unknown")),
		fmt.Sprintf("Violation: %s", primary.RuleLabel),
	}

	if primary.RuleTarget != "" && primary.RuleTarget != primary.Target {
		lines = append(lines, fmt.Sprintf("Matched rule: %s", primary.RuleTarget))
	}

	if primary.RawLog != "" {
		lines = append(lines, fmt.Sprintf("Seatbelt log: %s", primary.RawLog))
	}

	if len(report.Violations) > 1 {
		lines = append(lines, fmt.Sprintf("Additional denials observed: %d", len(report.Violations)-1))
	}

	return strings.Join(lines, "\n")
}

func suggestOverride(v Violation) string {
	if !isSafeOverrideTarget(v.Target) {
		return ""
	}

	quotedTarget := shellQuote(v.Target)

	switch v.Kind {
	case ViolationKindFSRead:
		return fmt.Sprintf("--sandbox-allow read=%s", quotedTarget)
	case ViolationKindFSWrite, ViolationKindFSDeleteOrRename:
		return fmt.Sprintf("--sandbox-allow write=%s", quotedTarget)
	case ViolationKindExec:
		return fmt.Sprintf("--sandbox-allow exec=%s", quotedTarget)
	default:
		return ""
	}
}

func primaryViolation(report *ViolationReport) *Violation {
	if report == nil || len(report.Violations) == 0 {
		return nil
	}

	cwd, _ := os.Getwd()
	bestIdx := 0
	bestScore := scoreViolation(report.SandboxName, report.Violations[0], cwd)

	for i := 1; i < len(report.Violations); i++ {
		score := scoreViolation(report.SandboxName, report.Violations[i], cwd)
		if score >= bestScore {
			bestIdx = i
			bestScore = score
		}
	}

	return &report.Violations[bestIdx]
}

func scoreViolation(driver DriverName, v Violation, cwd string) int {
	score := 0

	switch v.Kind {
	case ViolationKindFSRead, ViolationKindFSWrite:
		score += 120
	case ViolationKindExec:
		score += 110
	case ViolationKindFSDeleteOrRename:
		score += 100
	case ViolationKindGenericDeny:
		score += 10
	default:
		score += 30
	}

	if isSafeOverrideTarget(v.Target) {
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

	if isNoisySystemPath(driver, v.Target) {
		score -= 120
	}

	if v.Kind == ViolationKindGenericDeny && v.Target == "" {
		score -= 40
	}

	return score
}

func isSafeOverrideTarget(value string) bool {
	if value == "" {
		return false
	}

	if strings.ContainsAny(value, "*?[]") {
		return false
	}

	for _, r := range value {
		if r == 0 || r < 0x20 || r == 0x7f {
			return false
		}
	}

	return true
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func emptyFallback(value, fallback string) string {
	if value == "" {
		return fallback
	}

	return value
}

func isProjectPath(target, cwd string) bool {
	if target == "" || cwd == "" {
		return false
	}

	if strings.HasPrefix(target, ".") {
		return !isParentRelativePath(target)
	}

	cleanTarget := filepath.Clean(target)
	cleanCwd := filepath.Clean(cwd)

	return cleanTarget == cleanCwd || strings.HasPrefix(cleanTarget, cleanCwd+string(filepath.Separator))
}

func isSensitiveProjectFile(target string) bool {
	if target == "" || isParentRelativePath(target) {
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

func isParentRelativePath(target string) bool {
	cleanTarget := filepath.Clean(target)
	return cleanTarget == ".." || strings.HasPrefix(cleanTarget, ".."+string(filepath.Separator))
}

func isNoisySystemPath(driver DriverName, target string) bool {
	if driver != DriverSeatbelt {
		return false
	}

	switch target {
	case "/dev/dtracehelper", "/dev/tty":
		return true
	default:
		return strings.HasPrefix(target, "/dev/ttys")
	}
}
