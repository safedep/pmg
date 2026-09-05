package sandbox

// BuildAllOverrides maps every safe FS, exec and env-scrub violation in report
// to an OverrideSuggestion. Network violations are intentionally skipped: an
// allowance for them is a host:port rule, not a target. Returns nil when the
// report is empty or OutputDerived, since forgeable evidence must not become a
// persisted allowance. Duplicates (same Kind+Target) are collapsed so callers
// do not have to de-dup against the existing overlay before passing the result
// through.
func BuildAllOverrides(report *ViolationReport) []OverrideSuggestion {
	if report == nil || len(report.Violations) == 0 || report.OutputDerived {
		return nil
	}

	seen := make(map[OverrideSuggestion]struct{}, len(report.Violations))
	out := make([]OverrideSuggestion, 0, len(report.Violations))
	for i := range report.Violations {
		sugg := overrideSuggestion(report.Violations[i])
		if sugg == nil {
			continue
		}
		if _, dup := seen[*sugg]; dup {
			continue
		}
		seen[*sugg] = struct{}{}
		out = append(out, *sugg)
	}
	return out
}
