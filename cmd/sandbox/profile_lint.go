package sandbox

import (
	"fmt"
	"io"
	"os"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/ui"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

const ExitCodeLintFail = 2

type profileLintOptions struct {
	strict  bool
	verbose bool
	jsonOut bool
}

func newProfileLintCommand(factory registryFactory) *cobra.Command {
	opts := &profileLintOptions{}

	cmd := &cobra.Command{
		Use:           "lint <path|name>",
		Short:         "Lint a sandbox profile for schema issues, overly broad rules, and conflicts",
		Example:       "  pmg sandbox profile lint npm-restrictive\n  pmg sandbox profile lint ./my-profile.yml --strict",
		Args:          cobra.ExactArgs(1),
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runProfileLint(cmd.OutOrStdout(), args[0], opts, factory)
			if err != nil {
				if _, isFail := err.(*lintFailError); isFail {
					cmd.SilenceErrors = true
					cmd.SilenceUsage = true
					return err
				}
				return sandboxErrorExit(cmd, err)
			}
			return err
		},
	}

	cmd.Flags().BoolVar(&opts.strict, "strict", false, "Treat warnings as errors (non-zero exit)")
	cmd.Flags().BoolVar(&opts.verbose, "verbose", false, "Include info-level issues")
	cmd.Flags().BoolVar(&opts.jsonOut, "json", false, "Emit lint results as JSON")
	return cmd
}

type lintFailError struct{}

func (e *lintFailError) Error() string { return "" }
func (e *lintFailError) ExitCode() int { return ExitCodeLintFail }

func runProfileLint(out io.Writer, name string, opts *profileLintOptions, factory registryFactory) error {
	registry, err := factory()
	if err != nil {
		return err
	}

	policy, resolvedName, err := resolveProfileForLint(name, registry)
	if err != nil {
		return err
	}

	issues := pmgsandbox.LintProfile(policy)
	if !opts.verbose {
		issues = filterInfo(issues)
	}

	if opts.jsonOut {
		if err := writeLintJSON(out, resolvedName, issues); err != nil {
			return err
		}
	} else {
		if err := renderLintHuman(out, resolvedName, issues); err != nil {
			return err
		}
	}

	if shouldFailLint(issues, opts.strict) {
		return &lintFailError{}
	}
	return nil
}

func resolveProfileForLint(name string, registry pmgsandbox.ProfileRegistry) (*pmgsandbox.SandboxPolicy, string, error) {
	if _, ok := registry.BuiltinProfileYAML(name); ok {
		policy, err := registry.GetProfile(name)
		if err != nil {
			return nil, "", err
		}
		return policy, name, nil
	}

	summaries, err := registry.ListProfiles()
	if err != nil {
		log.Warnf("sandbox: failed to enumerate user profiles: %v", err)
	}
	for _, s := range summaries {
		if s.Source == pmgsandbox.ProfileSourceUser && s.Name == name {
			policy, loadErr := registry.LoadCustomProfile(s.Path)
			if loadErr != nil {
				return nil, "", loadErr
			}
			return policy, s.Path, nil
		}
	}

	if _, statErr := os.Stat(name); statErr == nil {
		policy, loadErr := registry.LoadCustomProfile(name)
		if loadErr != nil {
			return nil, "", loadErr
		}
		return policy, name, nil
	}

	return nil, "", notFoundError(
		fmt.Sprintf("sandbox profile not found: %s", name),
		"Use `pmg sandbox profile list` to see available profiles, or pass an existing profile YAML path.",
	)
}

func filterInfo(issues []pmgsandbox.LintIssue) []pmgsandbox.LintIssue {
	out := make([]pmgsandbox.LintIssue, 0, len(issues))
	for _, i := range issues {
		if i.Level == pmgsandbox.LintLevelInfo {
			continue
		}
		out = append(out, i)
	}
	return out
}

func shouldFailLint(issues []pmgsandbox.LintIssue, strict bool) bool {
	for _, i := range issues {
		if i.Level == pmgsandbox.LintLevelError {
			return true
		}
		if strict && i.Level == pmgsandbox.LintLevelWarn {
			return true
		}
	}
	return false
}

type jsonLintReport struct {
	Profile string                 `json:"profile"`
	Issues  []pmgsandbox.LintIssue `json:"issues"`
}

func writeLintJSON(out io.Writer, profile string, issues []pmgsandbox.LintIssue) error {
	if issues == nil {
		issues = []pmgsandbox.LintIssue{}
	}
	return writeJSONIndent(out, jsonLintReport{Profile: profile, Issues: issues})
}

func renderLintHuman(out io.Writer, profile string, issues []pmgsandbox.LintIssue) error {
	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, ui.Colors.Cyan("Profile Lint: ")+ui.Colors.Bold(profile)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, ui.Colors.Normal("---------------")); err != nil {
		return err
	}

	if len(issues) == 0 {
		_, err := fmt.Fprintln(out, ui.Colors.Green("OK")+" no issues found")
		return err
	}

	rows := make([][]string, 0, len(issues)+1)
	rows = append(rows, []string{
		ui.Colors.Bold("LEVEL"),
		ui.Colors.Bold("CODE"),
		ui.Colors.Bold("FIELD"),
		ui.Colors.Bold("MESSAGE"),
	})
	for _, i := range issues {
		rows = append(rows, []string{
			lintLevelBadge(i.Level),
			i.Code,
			i.Field,
			i.Message,
		})
	}

	indent := firstColumnIndent(rows)
	return renderTable(out, rows, func(dataIdx int) error {
		if dataIdx < 0 {
			return nil
		}
		issue := issues[dataIdx]
		if issue.Rule == "" {
			return nil
		}
		_, err := fmt.Fprintf(out, "%s%s %s\n", indent, ui.Colors.Dim("rule:"), ui.Colors.Dim(issue.Rule))
		return err
	})
}

func lintLevelBadge(level pmgsandbox.LintLevel) string {
	switch level {
	case pmgsandbox.LintLevelError:
		return ui.Colors.Red("ERROR")
	case pmgsandbox.LintLevelWarn:
		return ui.Colors.Yellow("WARN")
	case pmgsandbox.LintLevelInfo:
		return ui.Colors.Dim("INFO")
	}
	return string(level)
}
