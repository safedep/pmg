package sandbox

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Explanation is structured data extracted from a ViolationReport. It carries
// only domain facts — the human-readable rendering and any CLI-specific
// suggestion strings (flag names, line layout) belong to the presentation
// layer (see internal/ui).
type Explanation struct {
	// Primary is the violation most likely to be actionable, chosen by
	// scoreViolation. Nil when the report contains no violations.
	Primary *Violation

	// Override carries a structured override hint for the primary violation
	// (kind + target) when one can be safely suggested. Nil when no safe
	// suggestion is available (glob targets, control characters, unsupported
	// violation kinds). The presentation layer decides how to render this as a
	// CLI flag, an API hint, etc.
	Override *OverrideSuggestion

	// AdditionalDenials counts denials beyond Primary so callers can show
	// "+N more" without re-walking the report. Env scrubs are not denials
	// and are excluded.
	AdditionalDenials int
}

// OverrideSuggestion is the structured form of a "you can re-run with this
// allowance" hint. Kind tells the consumer which permission would unblock the
// operation; Target is the path/exec the user would whitelist.
type OverrideSuggestion struct {
	Kind   ViolationKind
	Target string
}

// BuildExplanation produces an Explanation for the given report. An
// OutputDerived report yields no Override, since its evidence is forgeable.
func BuildExplanation(report *ViolationReport) Explanation {
	primary := primaryViolation(report)
	exp := Explanation{Primary: primary}
	if primary != nil {
		if !report.OutputDerived {
			exp.Override = overrideSuggestion(*primary)
		}

		denials := 0
		for _, v := range report.Violations {
			if v.Kind != ViolationKindEnvScrub {
				denials++
			}
		}
		if primary.Kind != ViolationKindEnvScrub {
			denials--
		}
		if denials > 0 {
			exp.AdditionalDenials = denials
		}
	}
	return exp
}

// Suggestions are rendered into a shell command, so env names are held to the
// conventional form rather than everything execve permits in a variable name.
var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// IsConventionalEnvName reports whether name has the conventional environment
// variable form. The suggestion gate and the render site both hold names to
// this form before a name goes into a shell command.
func IsConventionalEnvName(name string) bool {
	return envNameRe.MatchString(name)
}

func overrideSuggestion(v Violation) *OverrideSuggestion {
	switch v.Kind {
	case ViolationKindFSRead,
		ViolationKindFSWrite,
		ViolationKindFSDeleteOrRename,
		ViolationKindExec:
		if !isSafeOverrideTarget(v.Target) {
			return nil
		}
	case ViolationKindEnvScrub:
		if !IsConventionalEnvName(v.Target) {
			return nil
		}
	default:
		return nil
	}

	return &OverrideSuggestion{Kind: v.Kind, Target: v.Target}
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
	// Preemptive, not observed: ranks below every driver denial, and the
	// modifiers below read a path and say nothing about a variable name.
	if v.Kind == ViolationKindEnvScrub {
		return 45
	}

	score := 0

	switch v.Kind {
	case ViolationKindFSRead, ViolationKindFSWrite:
		score += 120
	case ViolationKindExec:
		score += 110
	case ViolationKindNetworkBind, ViolationKindNetworkConnect:
		score += 105
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

// IsSensitiveProjectTarget reports whether target points to a known sensitive
// file or directory (credential stores, dotfiles like .env/.npmrc). Used by
// the overlay save-time guard to refuse implicit credential allowances.
func IsSensitiveProjectTarget(target string) bool {
	return isSensitiveProjectFile(target)
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
			strings.Contains(target, string(filepath.Separator)+".kube") ||
			strings.Contains(target, string(filepath.Separator)+".gnupg")
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
