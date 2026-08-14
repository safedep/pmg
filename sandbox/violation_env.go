package sandbox

// MergeEnvScrub folds environment scrubs into a driver's violation report,
// synthesizing one from the scrub record when the driver reported nothing.
// Returns report unchanged when there is nothing to merge.
func MergeEnvScrub(report *ViolationReport, scrub EnvScrub) *ViolationReport {
	violations := envScrubViolations(scrub)
	if len(violations) == 0 {
		return report
	}

	if report == nil {
		return &ViolationReport{
			SandboxName: scrub.SandboxName,
			PolicyName:  scrub.PolicyName,
			Violations:  violations,
		}
	}

	report.Violations = append(report.Violations, violations...)
	return report
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
