package sandbox

import (
	"fmt"
	"io"
	"strings"

	"github.com/safedep/pmg/internal/ui"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

type profileListOptions struct {
	jsonOut bool
}

func newProfileListCommand(factory registryFactory) *cobra.Command {
	opts := &profileListOptions{}

	cmd := &cobra.Command{
		Use:           "list",
		Short:         "List available sandbox profiles (built-in and user)",
		Example:       "  pmg sandbox profile list",
		SilenceErrors: false,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runProfileList(cmd.OutOrStdout(), opts, factory)
			if err != nil {
				return sandboxErrorExit(cmd, err)
			}
			return err
		},
	}

	cmd.Flags().BoolVar(&opts.jsonOut, "json", false, "Emit profiles as JSON")
	return cmd
}

func runProfileList(out io.Writer, opts *profileListOptions, factory registryFactory) error {
	registry, err := factory()
	if err != nil {
		return err
	}

	summaries, err := registry.ListProfiles()
	if err != nil {
		return err
	}

	if opts.jsonOut {
		return writeProfileListJSON(out, summaries)
	}

	return renderProfileListHuman(out, summaries)
}

type jsonProfileSummary struct {
	Name            string   `json:"name"`
	Source          string   `json:"source"`
	Path            string   `json:"path,omitempty"`
	Inherits        string   `json:"inherits,omitempty"`
	PackageManagers []string `json:"package_managers,omitempty"`
	Description     string   `json:"description,omitempty"`
	Shadowed        bool     `json:"shadowed,omitempty"`
}

type jsonProfileListReport struct {
	Profiles []jsonProfileSummary `json:"profiles"`
}

func writeProfileListJSON(out io.Writer, summaries []pmgsandbox.ProfileSummary) error {
	report := jsonProfileListReport{Profiles: make([]jsonProfileSummary, 0, len(summaries))}
	for _, s := range summaries {
		report.Profiles = append(report.Profiles, jsonProfileSummary{
			Name:            s.Name,
			Source:          string(s.Source),
			Path:            s.Path,
			Inherits:        s.Inherits,
			PackageManagers: s.PackageManagers,
			Description:     s.Description,
			Shadowed:        s.Shadowed,
		})
	}

	return writeJSONIndent(out, report)
}

func renderProfileListHuman(out io.Writer, summaries []pmgsandbox.ProfileSummary) error {
	if len(summaries) == 0 {
		_, err := fmt.Fprintln(out, ui.Colors.Dim("No sandbox profiles available."))
		return err
	}

	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, ui.Colors.Cyan("Sandbox Profiles")); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, ui.Colors.Normal("-----------------")); err != nil {
		return err
	}

	rows := make([][]string, 0, len(summaries)+1)
	rows = append(rows, []string{
		ui.Colors.Bold("STATUS"),
		ui.Colors.Bold("NAME"),
		ui.Colors.Bold("SOURCE"),
		ui.Colors.Bold("INHERITS"),
		ui.Colors.Bold("PMS"),
		ui.Colors.Bold("DESCRIPTION"),
	})
	for _, s := range summaries {
		rows = append(rows, []string{
			statusCell(s),
			s.Name,
			sourceCell(s),
			emptyDash(s.Inherits),
			truncate(strings.Join(s.PackageManagers, ","), 30),
			truncate(s.Description, 60),
		})
	}

	return renderTable(out, rows, nil)
}

func statusCell(s pmgsandbox.ProfileSummary) string {
	if s.Shadowed {
		return ui.Colors.Dim("SHADOWED")
	}
	return " "
}

func sourceCell(s pmgsandbox.ProfileSummary) string {
	if s.Source == pmgsandbox.ProfileSourceBuiltin {
		return ui.Colors.Dim("builtin")
	}
	return truncateLeft(s.Path, 50)
}

func emptyDash(s string) string {
	if s == "" {
		return ui.Colors.Dim("—")
	}
	return s
}
