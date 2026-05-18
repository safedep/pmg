package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/ui"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/usefulerror"
	"github.com/spf13/cobra"
)

// ExitCodeExplainFail is returned when explain cannot produce output.
const ExitCodeExplainFail = 2

// cacheFactory returns the ViolationCache used to look up cached reports.
type cacheFactory func() *pmgsandbox.ViolationCache

type explainOptions struct {
	last    bool
	jsonOut bool
}

// NewExplainCommand returns the `pmg sandbox explain` subcommand.
func NewExplainCommand() *cobra.Command {
	return newExplainCommand(func() *pmgsandbox.ViolationCache {
		return pmgsandbox.NewViolationCache(config.Get().SandboxViolationCacheDir())
	})
}

// newExplainCommand allows callers (tests) to inject a cache factory.
func newExplainCommand(factory cacheFactory) *cobra.Command {
	opts := &explainOptions{}

	cmd := &cobra.Command{
		Use:           "explain [--last | -]",
		Short:         "Explain a sandbox violation from the local cache or piped JSON",
		Example:       "  pmg sandbox explain --last\n  pmg sandbox explain - < violation.json",
		SilenceErrors: false,
		Args:          cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runExplain(cmd.OutOrStdout(), cmd.InOrStdin(), args, opts, factory)
			if err != nil {
				return sandboxErrorExit(cmd, err)
			}
			return err
		},
	}

	cmd.Flags().BoolVar(&opts.last, "last", false, "Read the most recent cached violation report")
	cmd.Flags().BoolVar(&opts.jsonOut, "json", false, "Emit explanation and report as JSON")
	return cmd
}

// explainFailError carries a friendly message and a non-zero exit code.
type explainFailError struct {
	usefulerror.UsefulError
}

// ExitCode reports the explain exit code so main can propagate it.
func (e *explainFailError) ExitCode() int { return ExitCodeExplainFail }

func newExplainFailError(code, msg, help string) *explainFailError {
	return &explainFailError{
		UsefulError: usefulerror.Useful().
			WithCode(code).
			WithHumanError(msg).
			WithHelp(help).
			Wrap(errors.New(msg)),
	}
}

func runExplain(out io.Writer, in io.Reader, args []string, opts *explainOptions, factory cacheFactory) error {
	stdinMode := len(args) == 1 && args[0] == "-"

	if len(args) == 1 && !stdinMode {
		return newExplainFailError(
			usefulerror.ErrCodeInvalidArgument,
			fmt.Sprintf("unexpected argument %q (use --last or pipe JSON with `-`)", args[0]),
			explainUsageHelp(),
		)
	}

	if opts.last && stdinMode {
		return newExplainFailError(
			usefulerror.ErrCodeInvalidArgument,
			"--last and `-` are mutually exclusive",
			explainUsageHelp(),
		)
	}

	if !opts.last && !stdinMode {
		return newExplainFailError(
			usefulerror.ErrCodeInvalidArgument,
			"no input: pass --last to read the most recent cached violation, or pipe a violation record JSON on stdin with `-`",
			explainUsageHelp(),
		)
	}

	var (
		record *pmgsandbox.ViolationCacheRecord
		err    error
	)

	if opts.last {
		record, err = readLatestFromCache(factory)
	} else {
		record, err = readRecordFromStdin(in)
	}
	if err != nil {
		return err
	}

	if opts.jsonOut {
		return writeExplainJSON(out, record)
	}

	return renderExplanation(out, record)
}

func readLatestFromCache(factory cacheFactory) (*pmgsandbox.ViolationCacheRecord, error) {
	cache := factory()
	entry, err := cache.Latest()
	if err != nil {
		return nil, newExplainFailError(
			usefulerror.ErrCodeUnknown,
			fmt.Sprintf("read cache: %v", err),
			"Check the sandbox violation cache directory and retry.",
		)
	}
	if entry == nil {
		return nil, newExplainFailError(
			usefulerror.ErrCodeNotFound,
			"no violations cached yet — run a sandboxed command first",
			"Run a sandboxed package manager command first, then retry `pmg sandbox explain --last`.",
		)
	}
	rec := entry.Record
	if err := validateViolationCacheRecord(&rec, "cache JSON"); err != nil {
		return nil, err
	}
	return &rec, nil
}

func readRecordFromStdin(in io.Reader) (*pmgsandbox.ViolationCacheRecord, error) {
	data, err := io.ReadAll(in)
	if err != nil {
		return nil, newExplainFailError(
			usefulerror.ErrCodeInvalidArgument,
			fmt.Sprintf("read stdin: %v", err),
			explainUsageHelp(),
		)
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, newExplainFailError(
			usefulerror.ErrCodeInvalidArgument,
			"stdin is empty: pipe a ViolationCacheRecord JSON document",
			explainUsageHelp(),
		)
	}

	var rec pmgsandbox.ViolationCacheRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, newExplainFailError(
			usefulerror.ErrCodeInvalidArgument,
			fmt.Sprintf("parse stdin JSON: %v", err),
			"Pipe a valid ViolationCacheRecord JSON document to `pmg sandbox explain -`.",
		)
	}

	if err := validateViolationCacheRecord(&rec, "stdin JSON"); err != nil {
		return nil, err
	}

	return &rec, nil
}

func validateViolationCacheRecord(rec *pmgsandbox.ViolationCacheRecord, source string) error {
	if rec == nil {
		return newExplainFailError(usefulerror.ErrCodeInvalidArgument, fmt.Sprintf("%s is empty", source), explainUsageHelp())
	}
	if rec.SchemaVersion == 0 {
		return newExplainFailError(usefulerror.ErrCodeInvalidArgument, fmt.Sprintf("%s is missing schema_version", source), explainUsageHelp())
	}
	if rec.SchemaVersion != pmgsandbox.ViolationCacheSchemaVersion {
		return newExplainFailError(usefulerror.ErrCodeInvalidArgument, fmt.Sprintf("unknown schema_version %d (expected %d)", rec.SchemaVersion, pmgsandbox.ViolationCacheSchemaVersion), explainUsageHelp())
	}
	if rec.Report == nil {
		return newExplainFailError(usefulerror.ErrCodeInvalidArgument, fmt.Sprintf("%s is missing report", source), explainUsageHelp())
	}

	return nil
}

func explainUsageHelp() string {
	return "Use `pmg sandbox explain --last` or pipe a violation record JSON with `pmg sandbox explain -`."
}

// --- Human rendering ----------------------------------------------------

func renderExplanation(out io.Writer, rec *pmgsandbox.ViolationCacheRecord) error {
	exp := pmgsandbox.BuildExplanation(rec.Report)

	recordedAt := ""
	if !rec.RecordedAt.IsZero() {
		recordedAt = rec.RecordedAt.UTC().Format(time.RFC3339)
	}

	header := fmt.Sprintf("%s %s  %s %s",
		ui.Colors.Dim("Sandbox:"), ui.Colors.Bold(string(rec.Report.SandboxName)),
		ui.Colors.Dim("Profile:"), ui.Colors.Bold(rec.Report.PolicyName),
	)
	if recordedAt != "" {
		header = fmt.Sprintf("%s  %s %s", header, ui.Colors.Dim("Recorded:"), ui.Colors.Normal(recordedAt))
	}

	if _, err := fmt.Fprintln(out, header); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, ui.Colors.Normal("--------------------------------------------------------")); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}

	if exp.Hint != "" {
		if _, err := fmt.Fprintln(out, exp.Hint); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
	}

	if exp.Details != "" {
		if _, err := fmt.Fprintln(out, ui.Colors.Bold("Details:")); err != nil {
			return err
		}
		for _, line := range strings.Split(exp.Details, "\n") {
			if _, err := fmt.Fprintf(out, "  %s\n", line); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
	}

	if exp.SuggestedOverride != "" {
		if _, err := fmt.Fprintln(out, ui.Colors.Bold("Suggested override:")); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "  %s\n", ui.Colors.Cyan(exp.SuggestedOverride)); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
	}

	if exp.Primary != nil {
		if _, err := fmt.Fprintln(out, ui.Colors.Bold("Primary violation:")); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "  %s   %s\n", ui.Colors.Dim("Kind:"), string(exp.Primary.Kind)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "  %s %s\n", ui.Colors.Dim("Target:"), exp.Primary.Target); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "  %s   %s\n", ui.Colors.Dim("Rule:"), exp.Primary.RuleLabel); err != nil {
			return err
		}
		if exp.Primary.Process != "" {
			if _, err := fmt.Fprintf(out, "  %s %s\n", ui.Colors.Dim("Process:"), exp.Primary.Process); err != nil {
				return err
			}
		}
	}

	return nil
}

// --- JSON output --------------------------------------------------------

type explainJSONPrimary struct {
	Kind       string `json:"kind"`
	RawKind    string `json:"raw_kind,omitempty"`
	Target     string `json:"target,omitempty"`
	RuleTarget string `json:"rule_target,omitempty"`
	Process    string `json:"process,omitempty"`
	RawLog     string `json:"raw_log,omitempty"`
	RuleLabel  string `json:"rule_label,omitempty"`
}

type explainJSONExplanation struct {
	Hint              string              `json:"hint"`
	Details           string              `json:"details"`
	SuggestedOverride string              `json:"suggested_override"`
	Primary           *explainJSONPrimary `json:"primary"`
}

type explainJSONOutput struct {
	Explanation explainJSONExplanation      `json:"explanation"`
	Report      *pmgsandbox.ViolationReport `json:"report"`
	RecordedAt  string                      `json:"recorded_at,omitempty"`
}

func writeExplainJSON(out io.Writer, rec *pmgsandbox.ViolationCacheRecord) error {
	if rec == nil || rec.Report == nil {
		return errors.New("explain: empty record")
	}

	exp := pmgsandbox.BuildExplanation(rec.Report)

	payload := explainJSONOutput{
		Explanation: explainJSONExplanation{
			Hint:              exp.Hint,
			Details:           exp.Details,
			SuggestedOverride: exp.SuggestedOverride,
		},
		Report: rec.Report,
	}

	if exp.Primary != nil {
		payload.Explanation.Primary = &explainJSONPrimary{
			Kind:       string(exp.Primary.Kind),
			RawKind:    exp.Primary.RawKind,
			Target:     exp.Primary.Target,
			RuleTarget: exp.Primary.RuleTarget,
			Process:    exp.Primary.Process,
			RawLog:     exp.Primary.RawLog,
			RuleLabel:  exp.Primary.RuleLabel,
		}
	}

	if !rec.RecordedAt.IsZero() {
		payload.RecordedAt = rec.RecordedAt.UTC().Format(time.RFC3339)
	}

	return writeJSONIndent(out, payload)
}
