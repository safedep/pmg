package sandbox

import (
	"context"
	"fmt"
	"io"

	"github.com/safedep/pmg/internal/ui"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/platform"
	"github.com/spf13/cobra"
)

type doctorOptions struct {
	jsonOut bool
	driver  string
}

func NewDoctorCommand() *cobra.Command {
	return newDoctorCommand(platform.DefaultProbes)
}

func newDoctorCommand(probes func() []pmgsandbox.Probe) *cobra.Command {
	opts := &doctorOptions{}

	cmd := &cobra.Command{
		Use:           "doctor",
		Short:         "Run sandbox probes and report on host readiness",
		Example:       "  pmg sandbox doctor\n  pmg sandbox doctor --driver landlock",
		Args:          cobra.NoArgs,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runDoctor(cmd.Context(), cmd.OutOrStdout(), opts, probes)
			if err != nil {
				if _, isFail := err.(*doctorFailError); isFail {
					cmd.SilenceErrors = true
					cmd.SilenceUsage = true
					return err
				}
				return sandboxErrorExit(cmd, err)
			}
			return err
		},
	}

	cmd.Flags().BoolVar(&opts.jsonOut, "json", false, "Emit probe results as JSON")
	cmd.Flags().StringVar(&opts.driver, "driver", "", "Filter probes to a single driver: seatbelt|bubblewrap|landlock")
	return cmd
}

func runDoctor(ctx context.Context, out io.Writer, opts *doctorOptions, probes func() []pmgsandbox.Probe) error {
	if err := validateDriver(opts.driver); err != nil {
		return err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	all := probes()
	filtered := filterByDriver(all, opts.driver)
	results := pmgsandbox.RunProbes(ctx, filtered)

	if opts.jsonOut {
		if err := writeJSON(out, results); err != nil {
			return err
		}
	} else {
		if err := renderHuman(out, results); err != nil {
			return err
		}
	}

	if exitCodeForResults(results) != 0 {
		return &doctorFailError{}
	}
	return nil
}

type doctorFailError struct{}

func (e *doctorFailError) Error() string { return "" }
func (e *doctorFailError) ExitCode() int { return ExitCodeProbeFailure }

func exitCodeForResults(results []pmgsandbox.ProbeResult) int {
	for _, r := range results {
		if r.Status == pmgsandbox.ProbeStatusFail {
			return ExitCodeProbeFailure
		}
	}
	return 0
}

// driverProbeNames lists which probes belong to each driver. The apparmor
// probe is shared by bubblewrap and landlock (both rely on unprivileged user
// namespaces on Linux) and excluded from the darwin-only seatbelt filter.
var driverProbeNames = map[pmgsandbox.DriverName]map[string]struct{}{
	pmgsandbox.DriverSeatbelt: {
		pmgsandbox.ProbeSeatbeltDriver: {},
		pmgsandbox.ProbeSeatbeltCanary: {},
	},
	pmgsandbox.DriverBubblewrap: {
		pmgsandbox.ProbeBwrapDriver:    {},
		pmgsandbox.ProbeBwrapCanary:    {},
		pmgsandbox.ProbeAppArmorUserns: {},
	},
	pmgsandbox.DriverLandlock: {
		pmgsandbox.ProbeLandlockDriver: {},
		pmgsandbox.ProbeLandlockCanary: {},
		pmgsandbox.ProbeAppArmorUserns: {},
	},
}

func filterByDriver(probes []pmgsandbox.Probe, driver string) []pmgsandbox.Probe {
	if driver == "" {
		return probes
	}
	want := driverProbeNames[pmgsandbox.DriverName(driver)]
	out := make([]pmgsandbox.Probe, 0, len(probes))
	for _, p := range probes {
		if _, ok := want[p.Name()]; ok {
			out = append(out, p)
		}
	}
	return out
}

type jsonFix struct {
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
	Docs        string `json:"docs,omitempty"`
}

type jsonProbeResult struct {
	Name    string    `json:"name"`
	Status  string    `json:"status"`
	Summary string    `json:"summary,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	Fixes   []jsonFix `json:"fixes,omitempty"`
}

type jsonReport struct {
	Results []jsonProbeResult `json:"results"`
}

func writeJSON(out io.Writer, results []pmgsandbox.ProbeResult) error {
	report := jsonReport{Results: make([]jsonProbeResult, 0, len(results))}
	for _, r := range results {
		fixes := make([]jsonFix, 0, len(r.Fixes))
		for _, f := range r.Fixes {
			fixes = append(fixes, jsonFix{Description: f.Description, Command: f.Command, Docs: f.Docs})
		}
		report.Results = append(report.Results, jsonProbeResult{
			Name:    r.Name,
			Status:  string(r.Status),
			Summary: r.Summary,
			Detail:  r.Detail,
			Fixes:   fixes,
		})
	}

	return writeJSONIndent(out, report)
}

func renderHuman(out io.Writer, results []pmgsandbox.ProbeResult) error {
	if len(results) == 0 {
		_, err := fmt.Fprintln(out, ui.Colors.Dim("No probes to run."))
		return err
	}

	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, ui.Colors.Cyan("Sandbox Diagnostics")); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, ui.Colors.Normal("--------------------")); err != nil {
		return err
	}

	rows := make([][]string, 0, len(results)+1)
	rows = append(rows, []string{
		ui.Colors.Bold("STATUS"),
		ui.Colors.Bold("CHECK"),
		ui.Colors.Bold("SUMMARY"),
		ui.Colors.Bold("FIX"),
	})
	for _, r := range results {
		rows = append(rows, []string{
			statusBadge(r.Status),
			displayName(r.Name),
			truncate(r.Summary, 60),
			fixHint(r.Fixes),
		})
	}

	if err := renderTable(out, rows, nil); err != nil {
		return err
	}

	for _, r := range results {
		if r.Status == pmgsandbox.ProbeStatusOK {
			continue
		}
		if err := renderDetail(out, r); err != nil {
			return err
		}
	}

	return nil
}

func renderDetail(out io.Writer, r pmgsandbox.ProbeResult) error {
	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "%s %s — %s\n", statusBadge(r.Status), ui.Colors.Bold(displayName(r.Name)), r.Summary); err != nil {
		return err
	}
	if r.Detail != "" {
		if _, err := fmt.Fprintf(out, "  %s\n", ui.Colors.Dim(r.Detail)); err != nil {
			return err
		}
	}
	for i, f := range r.Fixes {
		if _, err := fmt.Fprintf(out, "  %s %s\n", ui.Colors.Cyan(fmt.Sprintf("Fix %d:", i+1)), f.Description); err != nil {
			return err
		}
		if f.Command != "" {
			if _, err := fmt.Fprintf(out, "    %s %s\n", ui.Colors.Dim("$"), f.Command); err != nil {
				return err
			}
		}
		if f.Docs != "" {
			if _, err := fmt.Fprintf(out, "    %s %s\n", ui.Colors.Dim("docs:"), f.Docs); err != nil {
				return err
			}
		}
	}
	return nil
}

func statusBadge(s pmgsandbox.ProbeStatus) string {
	switch s {
	case pmgsandbox.ProbeStatusOK:
		return ui.Colors.Green("OK")
	case pmgsandbox.ProbeStatusWarn:
		return ui.Colors.Yellow("WARN")
	case pmgsandbox.ProbeStatusFail:
		return ui.Colors.Red("FAIL")
	case pmgsandbox.ProbeStatusSkipped:
		return ui.Colors.Dim("SKIPPED")
	default:
		return string(s)
	}
}

func fixHint(fixes []pmgsandbox.ProbeFix) string {
	if len(fixes) == 0 {
		return ui.Colors.Dim("—")
	}
	first := truncate(fixes[0].Description, 50)
	if len(fixes) > 1 {
		return fmt.Sprintf("%s %s", first, ui.Colors.Dim(fmt.Sprintf("(+%d more)", len(fixes)-1)))
	}
	return first
}

func displayName(probeName string) string {
	switch probeName {
	case pmgsandbox.ProbeSeatbeltDriver:
		return "Seatbelt driver"
	case pmgsandbox.ProbeBwrapDriver:
		return "Bubblewrap driver"
	case pmgsandbox.ProbeLandlockDriver:
		return "Landlock ABI"
	case pmgsandbox.ProbeAppArmorUserns:
		return "AppArmor user namespaces"
	case pmgsandbox.ProbeSeatbeltCanary:
		return "Seatbelt canary"
	case pmgsandbox.ProbeBwrapCanary:
		return "Bubblewrap canary"
	case pmgsandbox.ProbeLandlockCanary:
		return "Landlock canary"
	}
	return probeName
}
