package sandbox

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/safedep/pmg/internal/ui"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/spf13/cobra"
)

const ExitCodeViolationsListFail = 2

type violationsListOptions struct {
	limit   int
	jsonOut bool
}

type violationsListFailError struct {
	usefulerror.UsefulError
}

func (e *violationsListFailError) ExitCode() int { return ExitCodeViolationsListFail }

func newViolationsListFailError(code, msg, help string) *violationsListFailError {
	return &violationsListFailError{
		UsefulError: usefulerror.NewUsefulError().
			WithCode(code).
			WithHumanError(msg).
			WithHelp(help).
			Wrap(errors.New(msg)),
	}
}

func newViolationsListCommand(factory cacheFactory) *cobra.Command {
	opts := &violationsListOptions{}

	cmd := &cobra.Command{
		Use:           "list",
		Short:         "List cached sandbox violations as one-line summaries",
		Example:       "  pmg sandbox violations list --limit 20",
		SilenceErrors: false,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runViolationsList(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts, factory)
			if err != nil {
				return sandboxErrorExit(cmd, err)
			}
			return err
		},
	}

	cmd.Flags().IntVar(&opts.limit, "limit", 10, "Maximum number of entries to show (0 means all)")
	cmd.Flags().BoolVar(&opts.jsonOut, "json", false, "Emit entries as JSON")
	return cmd
}

func runViolationsList(out, errOut io.Writer, opts *violationsListOptions, factory cacheFactory) error {
	if opts.limit < 0 {
		return newViolationsListFailError(
			errcodes.InvalidArgument,
			fmt.Sprintf("invalid --limit %d (must be >= 0)", opts.limit),
			"Pass --limit 0 to show all entries, or a positive limit.",
		)
	}

	cache := factory()
	entries, err := cache.List()
	if err != nil {
		return newViolationsListFailError(
			errcodes.Unknown,
			fmt.Sprintf("read cache: %v", err),
			"Check the sandbox violation cache directory and retry.",
		)
	}

	if opts.limit > 0 && len(entries) > opts.limit {
		entries = entries[:opts.limit]
	}

	if opts.jsonOut {
		return writeViolationsListJSON(out, entries)
	}

	if len(entries) == 0 {
		_, err := fmt.Fprintln(errOut, "no violations cached")
		return err
	}

	return renderViolationsListTable(out, entries)
}

func renderViolationsListTable(out io.Writer, entries []pmgsandbox.ViolationCacheEntry) error {
	rows := make([][]string, 0, len(entries)+1)
	rows = append(rows, []string{
		ui.Colors.Bold("RECORDED"),
		ui.Colors.Bold("SANDBOX"),
		ui.Colors.Bold("PROFILE"),
		ui.Colors.Bold("KIND"),
		ui.Colors.Bold("TARGET"),
	})

	dash := ui.Colors.Dim("—")
	for _, e := range entries {
		recorded := ""
		if !e.Record.RecordedAt.IsZero() {
			recorded = e.Record.RecordedAt.UTC().Format(time.RFC3339)
		}

		sandboxName := ""
		profile := ""
		if e.Record.Report != nil {
			sandboxName = string(e.Record.Report.SandboxName)
			profile = e.Record.Report.PolicyName
		}

		kind := dash
		target := dash
		if e.Record.Report != nil {
			primary := pmgsandbox.BuildExplanation(e.Record.Report).Primary
			if primary != nil {
				if primary.Kind != "" {
					kind = string(primary.Kind)
				}
				if primary.Target != "" {
					target = truncate(primary.Target, 60)
				}
			}
		}

		rows = append(rows, []string{recorded, sandboxName, profile, kind, target})
	}

	return renderTable(out, rows, nil)
}

type violationsListJSONPrimary struct {
	Kind      string `json:"kind"`
	Target    string `json:"target,omitempty"`
	RuleLabel string `json:"rule_label,omitempty"`
}

type violationsListJSONEntry struct {
	Path           string                     `json:"path"`
	RecordedAt     string                     `json:"recorded_at,omitempty"`
	SandboxName    string                     `json:"sandbox_name,omitempty"`
	PolicyName     string                     `json:"policy_name,omitempty"`
	Primary        *violationsListJSONPrimary `json:"primary,omitempty"`
	ViolationCount int                        `json:"violation_count"`
}

type violationsListJSONOutput struct {
	Entries []violationsListJSONEntry `json:"entries"`
}

func writeViolationsListJSON(out io.Writer, entries []pmgsandbox.ViolationCacheEntry) error {
	payload := violationsListJSONOutput{Entries: make([]violationsListJSONEntry, 0, len(entries))}

	for _, e := range entries {
		item := violationsListJSONEntry{Path: e.Path}
		if !e.Record.RecordedAt.IsZero() {
			item.RecordedAt = e.Record.RecordedAt.UTC().Format(time.RFC3339)
		}

		if e.Record.Report != nil {
			item.SandboxName = string(e.Record.Report.SandboxName)
			item.PolicyName = e.Record.Report.PolicyName
			item.ViolationCount = len(e.Record.Report.Violations)

			primary := pmgsandbox.BuildExplanation(e.Record.Report).Primary
			if primary != nil {
				item.Primary = &violationsListJSONPrimary{
					Kind:      string(primary.Kind),
					Target:    primary.Target,
					RuleLabel: primary.RuleLabel,
				}
			}
		}

		payload.Entries = append(payload.Entries, item)
	}

	return writeJSONIndent(out, payload)
}
