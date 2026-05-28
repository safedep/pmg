package sandbox

// BuildAllOverrides maps every safe FS/exec violation in report to an
// OverrideSuggestion. Network violations are intentionally skipped because
// drivers do not classify network denials yet. Returns nil when the report is
// empty. Duplicates (same Kind+Target) are collapsed so callers do not have to
// de-dup against the existing overlay before passing the result through.
func BuildAllOverrides(report *ViolationReport) []OverrideSuggestion {
	if report == nil || len(report.Violations) == 0 {
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
