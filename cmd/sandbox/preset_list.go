package sandbox

import (
	"fmt"
	"io"
	"strings"

	"github.com/safedep/pmg/internal/ui"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

type presetListOptions struct {
	jsonOut bool
	author  string
	labels  []string
}

func newPresetListCommand(factory presetRegistryFactory) *cobra.Command {
	opts := &presetListOptions{}

	cmd := &cobra.Command{
		Use:           "list",
		Short:         "List available sandbox presets (built-in and user)",
		Example:       "  pmg sandbox preset list\n  pmg sandbox preset list --label dev-server --author SafeDep",
		SilenceErrors: false,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPresetList(cmd.OutOrStdout(), opts, factory); err != nil {
				return sandboxErrorExit(cmd, err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&opts.jsonOut, "json", false, "Emit presets as JSON")
	cmd.Flags().StringVar(&opts.author, "author", "", "Only presets by this author (case-insensitive)")
	cmd.Flags().StringArrayVar(&opts.labels, "label", nil, "Only presets carrying this label (repeatable, all must match)")
	return cmd
}

func runPresetList(out io.Writer, opts *presetListOptions, factory presetRegistryFactory) error {
	registry, err := factory()
	if err != nil {
		return presetRegistryError(err)
	}

	infos, err := registry.List()
	if err != nil {
		return presetRegistryError(err)
	}

	infos = pmgsandbox.FilterPresets(infos, pmgsandbox.PresetFilter{
		Author: opts.author,
		Labels: opts.labels,
	})

	if opts.jsonOut {
		return writePresetListJSON(out, infos)
	}

	return renderPresetListHuman(out, infos)
}

type jsonPresetSummary struct {
	Name        string   `json:"name"`
	Source      string   `json:"source"`
	Path        string   `json:"path,omitempty"`
	Author      string   `json:"author,omitempty"`
	Labels      []string `json:"labels,omitempty"`
	Description string   `json:"description,omitempty"`
	Shadowed    bool     `json:"shadowed,omitempty"`
}

type jsonPresetListReport struct {
	Presets []jsonPresetSummary `json:"presets"`
}

func writePresetListJSON(out io.Writer, infos []pmgsandbox.PresetInfo) error {
	report := jsonPresetListReport{Presets: make([]jsonPresetSummary, 0, len(infos))}
	for _, info := range infos {
		report.Presets = append(report.Presets, jsonPresetSummary{
			Name:        info.Preset.Name,
			Source:      string(info.Source),
			Path:        info.Path,
			Author:      info.Preset.Metadata.Author,
			Labels:      info.Preset.Metadata.Labels,
			Description: info.Preset.Description,
			Shadowed:    info.Shadowed,
		})
	}

	return writeJSONIndent(out, report)
}

func renderPresetListHuman(out io.Writer, infos []pmgsandbox.PresetInfo) error {
	if len(infos) == 0 {
		_, err := fmt.Fprintln(out, ui.Colors.Dim("No sandbox presets match."))
		return err
	}

	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, ui.Colors.Cyan("Sandbox Presets")); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, ui.Colors.Normal("----------------")); err != nil {
		return err
	}

	rows := make([][]string, 0, len(infos)+1)
	rows = append(rows, []string{
		ui.Colors.Bold("STATUS"),
		ui.Colors.Bold("NAME"),
		ui.Colors.Bold("SOURCE"),
		ui.Colors.Bold("AUTHOR"),
		ui.Colors.Bold("LABELS"),
		ui.Colors.Bold("DESCRIPTION"),
	})
	for _, info := range infos {
		rows = append(rows, []string{
			presetStatusCell(info),
			info.Preset.Name,
			presetSourceCell(info),
			emptyDash(info.Preset.Metadata.Author),
			truncate(strings.Join(info.Preset.Metadata.Labels, ","), 30),
			truncate(info.Preset.Description, 60),
		})
	}

	if err := renderTable(out, rows, nil); err != nil {
		return err
	}

	_, err := fmt.Fprintf(out, "\n%s\n",
		ui.Colors.Dim("Apply to this repo: pmg sandbox allow preset=<name>"))
	return err
}

func presetStatusCell(info pmgsandbox.PresetInfo) string {
	if info.Shadowed {
		return ui.Colors.Dim("SHADOWED")
	}
	return " "
}

func presetSourceCell(info pmgsandbox.PresetInfo) string {
	if info.Source == pmgsandbox.PresetSourceBuiltin {
		return ui.Colors.Dim("builtin")
	}
	return truncateLeft(info.Path, 50)
}
