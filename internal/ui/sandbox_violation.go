package ui

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	pmgsandbox "github.com/safedep/pmg/sandbox"
)

// FormatSandboxOverrideFlag renders an OverrideSuggestion as a `--sandbox-allow`
// CLI flag invocation. Returns "" when there is nothing safe to suggest.
//
// The flag name lives here (not in sandbox/) because it is CLI-surface owned
// by the cmd layer; the sandbox package only knows kind + target.
func FormatSandboxOverrideFlag(o *pmgsandbox.OverrideSuggestion) string {
	arg := sandboxAllowArg(o)
	if arg == "" {
		return ""
	}

	return "--sandbox-allow " + arg
}

// FormatSandboxAllowCommand renders an OverrideSuggestion as the `pmg sandbox
// allow` command that persists the same allowance for this repository. Returns
// "" for sensitive targets, which that command refuses without --force.
func FormatSandboxAllowCommand(o *pmgsandbox.OverrideSuggestion) string {
	arg := sandboxAllowArg(o)
	if arg == "" || pmgsandbox.IsSensitiveProjectTarget(o.Target) {
		return ""
	}

	return "pmg sandbox allow " + arg
}

func sandboxAllowArg(o *pmgsandbox.OverrideSuggestion) string {
	if o == nil {
		return ""
	}

	switch o.Kind {
	case pmgsandbox.ViolationKindFSRead:
		return "read=" + shellQuote(o.Target)
	case pmgsandbox.ViolationKindFSWrite, pmgsandbox.ViolationKindFSDeleteOrRename:
		return "write=" + shellQuote(o.Target)
	case pmgsandbox.ViolationKindExec:
		return "exec=" + shellQuote(o.Target)
	case pmgsandbox.ViolationKindEnvScrub:
		return "env=" + o.Target
	default:
		return ""
	}
}

// FormatSandboxHint produces the short, one-line "Reason: ... Override: ..."
// summary shown above the detail block.
func FormatSandboxHint(primary *pmgsandbox.Violation, override *pmgsandbox.OverrideSuggestion) string {
	if primary == nil {
		return "Reason: sandbox denied an operation"
	}

	hint := "Reason: " + primary.RuleLabel
	if flag := FormatSandboxOverrideFlag(override); flag != "" {
		hint += ". Override: " + flag
	}
	return hint
}

// FormatSandboxDetails produces the multi-line detail block shown beneath the
// hint. Each line is "Label: value"; callers indent as they see fit.
func FormatSandboxDetails(report *pmgsandbox.ViolationReport, primary *pmgsandbox.Violation) string {
	if primary == nil || report == nil {
		return ""
	}

	process := primary.Process
	if process == "" {
		process = "unknown"
	}

	lines := []string{
		"Sandbox: " + string(report.SandboxName),
		"Policy: " + report.PolicyName,
	}

	if report.CorrelationID != "" {
		lines = append(lines, "Correlation: "+report.CorrelationID)
	}

	lines = append(lines,
		"Process: "+process,
		"Violation: "+primary.RuleLabel,
	)

	if primary.RuleTarget != "" && primary.RuleTarget != primary.Target {
		lines = append(lines, "Matched rule: "+primary.RuleTarget)
	}

	if primary.RawLog != "" {
		lines = append(lines, "Raw log: "+primary.RawLog)
	}

	// Scrubs are listed separately and are not denials.
	denials := len(report.Violations) - len(pmgsandbox.EnvScrubNames(report))
	if primary.Kind != pmgsandbox.ViolationKindEnvScrub {
		denials--
	}
	if denials > 0 {
		lines = append(lines, fmt.Sprintf("Additional denials observed: %d", denials))
	}

	return strings.Join(lines, "\n")
}

// RenderSandboxViolation writes the full human-readable explanation for a
// cached violation record to out. cmd handlers should prefer this over
// re-implementing the layout — it owns the section ordering, colors, and
// separator conventions.
func RenderSandboxViolation(out io.Writer, rec *pmgsandbox.ViolationCacheRecord) error {
	if rec == nil || rec.Report == nil {
		return fmt.Errorf("render sandbox violation: empty record")
	}

	exp := pmgsandbox.BuildExplanation(rec.Report)

	recordedAt := ""
	if !rec.RecordedAt.IsZero() {
		recordedAt = rec.RecordedAt.UTC().Format(time.RFC3339)
	}

	header := fmt.Sprintf("%s %s  %s %s",
		Colors.Dim("Sandbox:"), Colors.Bold(string(rec.Report.SandboxName)),
		Colors.Dim("Profile:"), Colors.Bold(rec.Report.PolicyName),
	)
	if recordedAt != "" {
		header = fmt.Sprintf("%s  %s %s", header, Colors.Dim("Recorded:"), Colors.Normal(recordedAt))
	}

	if _, err := fmt.Fprintln(out, header); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, Colors.Normal("--------------------------------------------------------")); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}

	hint := FormatSandboxHint(exp.Primary, exp.Override)
	if hint != "" {
		if _, err := fmt.Fprintln(out, hint); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
	}

	details := FormatSandboxDetails(rec.Report, exp.Primary)
	if details != "" {
		if _, err := fmt.Fprintln(out, Colors.Bold("Details:")); err != nil {
			return err
		}
		for _, line := range strings.Split(details, "\n") {
			if _, err := fmt.Fprintf(out, "  %s\n", line); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
	}

	// The primary is rendered in full below, so drop it here.
	names := pmgsandbox.EnvScrubNames(rec.Report)
	if exp.Primary != nil && exp.Primary.Kind == pmgsandbox.ViolationKindEnvScrub {
		names = slices.DeleteFunc(names, func(n string) bool { return n == exp.Primary.Target })
	}

	if len(names) > 0 {
		if _, err := fmt.Fprintln(out, Colors.Bold("Environment variables scrubbed:")); err != nil {
			return err
		}
		for _, name := range names {
			if _, err := fmt.Fprintf(out, "  %s\n", name); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
	}

	if flag := FormatSandboxOverrideFlag(exp.Override); flag != "" {
		if _, err := fmt.Fprintln(out, Colors.Bold("Suggested override:")); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "  %s\n", Colors.Cyan(flag)); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
		// `pmg sandbox allow` refuses sensitive targets without --force, so
		// do not suggest a command that would immediately fail.
		if !pmgsandbox.IsSensitiveProjectTarget(exp.Override.Target) {
			if _, err := fmt.Fprintln(out, Colors.Dim("Remember for this project: pmg sandbox allow --last --all")); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(out); err != nil {
				return err
			}
		}
	}

	if exp.Primary != nil {
		if _, err := fmt.Fprintln(out, Colors.Bold("Primary violation:")); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "  %s   %s\n", Colors.Dim("Kind:"), string(exp.Primary.Kind)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "  %s %s\n", Colors.Dim("Target:"), exp.Primary.Target); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "  %s   %s\n", Colors.Dim("Rule:"), exp.Primary.RuleLabel); err != nil {
			return err
		}
		if exp.Primary.Process != "" {
			if _, err := fmt.Fprintf(out, "  %s %s\n", Colors.Dim("Process:"), exp.Primary.Process); err != nil {
				return err
			}
		}
	}

	return nil
}

// shellQuote wraps value in single quotes, escaping any embedded single
// quotes. Used so suggested override flags can be copy-pasted into a POSIX
// shell verbatim regardless of spaces or quotes in the target.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
