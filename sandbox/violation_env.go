package sandbox

import "strings"

// MergeEnvScrub folds environment scrubs into a driver's violation report,
// synthesizing one from the scrub record when the driver reported nothing.
// It appends to report.Violations in place. A report without a sandbox or
// policy name takes them from the scrub record. Returns report unchanged when
// there is nothing to merge.
func MergeEnvScrub(report *ViolationReport, scrub EnvScrub) *ViolationReport {
	violations := envScrubViolations(scrub)
	if len(violations) == 0 {
		return report
	}

	if report == nil {
		report = &ViolationReport{}
	}
	if report.SandboxName == "" {
		report.SandboxName = scrub.SandboxName
	}
	if report.PolicyName == "" {
		report.PolicyName = scrub.PolicyName
	}

	report.Violations = append(report.Violations, violations...)
	return report
}

// Name segments that mark a variable whose value is a secret. A name that
// only points at a credential file (GOOGLE_APPLICATION_CREDENTIALS) is not
// covered. An allowance for it exposes a path, and the sandbox still controls
// access to the file.
var secretEnvSegments = map[string]bool{
	"SECRET":   true,
	"TOKEN":    true,
	"PASSWORD": true,
	"PASSWD":   true,
	"KEY":      true,
	"APIKEY":   true,
	"AUTH":     true,
}

// Known secret-value names the segment rule misses. GOOGLE_CREDENTIALS can
// hold the service account key JSON inline, unlike
// GOOGLE_APPLICATION_CREDENTIALS, which holds a path.
var secretEnvNames = map[string]bool{
	"GOOGLE_CREDENTIALS": true,
}

// IsSecretEnvName reports whether the value of the variable named name is
// likely a secret. It matches whole underscore-separated segments without
// regard to case, so AWS_SECRET_ACCESS_KEY matches and
// GOOGLE_APPLICATION_CREDENTIALS does not. Known secret-value names that the
// segment rule misses match directly.
func IsSecretEnvName(name string) bool {
	upper := strings.ToUpper(name)
	if secretEnvNames[upper] {
		return true
	}

	for _, segment := range strings.Split(upper, "_") {
		if secretEnvSegments[segment] {
			return true
		}
	}

	return false
}

// NeedsForceToPersist reports whether `pmg sandbox allow` refuses to save
// the suggestion without --force. The UI uses it to hide a command that
// would fail.
func NeedsForceToPersist(o *OverrideSuggestion) bool {
	if o == nil {
		return false
	}

	if o.Kind == ViolationKindEnvScrub {
		return IsSecretEnvName(o.Target)
	}

	return IsSensitiveProjectTarget(o.Target)
}

// EnvScrubNames returns the names of the variables scrubbed during the run the
// report describes, for callers that surface only a single primary violation.
func EnvScrubNames(report *ViolationReport) []string {
	if report == nil {
		return nil
	}

	var names []string
	for _, v := range report.Violations {
		if v.Kind == ViolationKindEnvScrub {
			names = append(names, v.Target)
		}
	}

	return names
}

func envScrubViolations(scrub EnvScrub) []Violation {
	violations := make([]Violation, 0, len(scrub.Names))
	for _, name := range scrub.Names {
		// A malformed "=VALUE" entry in the parent environment yields no name.
		if name == "" {
			continue
		}

		violations = append(violations, Violation{
			Kind:      ViolationKindEnvScrub,
			Target:    name,
			Process:   scrub.Process,
			RuleLabel: "environment variable scrubbed: " + name,
		})
	}

	return violations
}
