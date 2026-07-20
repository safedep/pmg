package sandbox

import (
	"fmt"
	"io"
	"strings"

	"github.com/safedep/pmg/internal/ui"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

type presetShowOptions struct {
	jsonOut bool
}

func newPresetShowCommand(factory presetRegistryFactory) *cobra.Command {
	opts := &presetShowOptions{}

	cmd := &cobra.Command{
		Use:           "show <name>",
		Short:         "Show a sandbox preset's allowances, metadata and threat notes",
		Example:       "  pmg sandbox preset show git",
		SilenceErrors: false,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPresetShow(cmd.OutOrStdout(), args[0], opts, factory); err != nil {
				return sandboxErrorExit(cmd, err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&opts.jsonOut, "json", false, "Emit the preset as JSON")
	return cmd
}

func runPresetShow(out io.Writer, name string, opts *presetShowOptions, factory presetRegistryFactory) error {
	registry, err := factory()
	if err != nil {
		return presetRegistryError(err)
	}

	info, err := registry.Get(name)
	if err != nil {
		return presetLoadError(err)
	}

	if opts.jsonOut {
		return writeJSONIndent(out, jsonPresetSummaryWithRules(info))
	}

	return renderPresetShowHuman(out, info)
}

type jsonPresetDetail struct {
	jsonPresetSummary
	Filesystem  pmgsandbox.PresetFilesystem  `json:"filesystem,omitempty"`
	Network     pmgsandbox.PresetNetwork     `json:"network,omitempty"`
	Process     pmgsandbox.PresetProcess     `json:"process,omitempty"`
	Environment pmgsandbox.PresetEnvironment `json:"environment,omitempty"`
}

func jsonPresetSummaryWithRules(info *pmgsandbox.PresetInfo) jsonPresetDetail {
	return jsonPresetDetail{
		jsonPresetSummary: jsonPresetSummary{
			Name:        info.Preset.Name,
			Source:      string(info.Source),
			Path:        info.Path,
			Author:      info.Preset.Metadata.Author,
			Labels:      info.Preset.Metadata.Labels,
			Description: info.Preset.Description,
		},
		Filesystem:  info.Preset.Filesystem,
		Network:     info.Preset.Network,
		Process:     info.Preset.Process,
		Environment: info.Preset.Environment,
	}
}

// renderPresetShowHuman prints the original YAML: it carries the authored
// threat notes, which are the point of showing a preset before trusting it.
func renderPresetShowHuman(out io.Writer, info *pmgsandbox.PresetInfo) error {
	// The underline length is computed from the plain header, colored
	// variants embed ANSI escapes that would inflate it.
	plain := fmt.Sprintf("Preset %s (%s)", info.Preset.Name, info.Source)
	header := ui.Colors.Cyan(plain)
	if info.Path != "" {
		header = fmt.Sprintf("%s %s", header, ui.Colors.Dim(info.Path))
		plain = fmt.Sprintf("%s %s", plain, info.Path)
	}

	if _, err := fmt.Fprintf(out, "\n%s\n%s\n\n", header,
		ui.Colors.Normal(strings.Repeat("-", len(plain)))); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(out, strings.TrimRight(string(info.Raw), "\n")); err != nil {
		return err
	}

	_, err := fmt.Fprintf(out, "\n%s\n",
		ui.Colors.Dim(fmt.Sprintf("Apply to this repo: pmg sandbox allow preset=%s", info.Preset.Name)))
	return err
}
