package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/ghasummary"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/sandbox/propose"
	"github.com/spf13/cobra"
)

type githubSummaryOptions struct {
	report          string
	proposal        string
	profile         string
	failOnViolation bool
}

// newGitHubSummaryCommand is the job summary step of the PMG GitHub
// Action. It is hidden, because its flags follow the action, not users.
func newGitHubSummaryCommand() *cobra.Command {
	opts := &githubSummaryOptions{}
	cmd := &cobra.Command{
		Use:          "github-summary",
		Short:        "Write the GitHub Actions job summary from a stop report",
		Hidden:       true,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := runGitHubSummary(cmd.OutOrStdout(), opts, os.Getenv("GITHUB_STEP_SUMMARY")); err != nil {
				ui.ErrorExit(err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.report, "report", "", "Stop report that `pmg proxy stop --report` wrote")
	cmd.Flags().StringVar(&opts.proposal, "proposal", "", "Proposal that `pmg sandbox profile propose --json` printed")
	cmd.Flags().StringVar(&opts.profile, "profile", "", "Network profile path the workflow names")
	cmd.Flags().BoolVar(&opts.failOnViolation, "fail-on-violation", false, "The job fails on a violation")
	return cmd
}

// runGitHubSummary appends the summary to the step summary file, or writes
// it to out when there is none, then writes the workflow commands to out.
func runGitHubSummary(out io.Writer, opts *githubSummaryOptions, summaryPath string) error {
	if opts.report == "" {
		return errors.New("--report is required")
	}
	in := ghasummary.Input{Profile: opts.profile, FailOnViolation: opts.failOnViolation, Workspace: os.Getenv("GITHUB_WORKSPACE")}
	if err := readJSON(opts.report, &in.Stop); err != nil {
		return err
	}
	if opts.proposal != "" {
		in.Proposal = &propose.Report{}
		if err := readJSON(opts.proposal, in.Proposal); err != nil {
			return err
		}
	}

	if err := writeSummary(out, summaryPath, ghasummary.Markdown(in)); err != nil {
		return err
	}
	for _, line := range ghasummary.Commands(in) {
		if _, err := fmt.Fprintln(out, line); err != nil {
			return err
		}
	}
	return nil
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return usefulerror.NewUsefulError().
			WithCode(errcodes.NotFound).
			WithHumanError(fmt.Sprintf("Cannot read %s", path)).
			WithHelp("Pass the file that `pmg proxy stop --report` or `pmg sandbox profile propose --json` wrote.").
			Wrap(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return usefulerror.NewUsefulError().
			WithCode(errcodes.InvalidArgument).
			WithHumanError(fmt.Sprintf("%s is not valid JSON", path)).
			WithHelp("Pass the file that `pmg proxy stop --report` or `pmg sandbox profile propose --json` wrote.").
			Wrap(err)
	}
	return nil
}

func writeSummary(out io.Writer, path, markdown string) error {
	if path == "" {
		_, err := io.WriteString(out, markdown)
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, werr := io.WriteString(f, markdown)
	return errors.Join(werr, f.Close())
}
