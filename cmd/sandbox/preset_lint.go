package sandbox

import (
	"fmt"
	"io"
	"os"

	"github.com/safedep/pmg/internal/ui"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

func newPresetLintCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "lint <file>...",
		Short:         "Validate preset YAML files against the preset schema",
		Example:       "  pmg sandbox preset lint ./my-preset.yml",
		SilenceErrors: false,
		Args:          cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPresetLint(cmd.OutOrStdout(), args); err != nil {
				return sandboxErrorExit(cmd, err)
			}
			return nil
		},
	}

	return cmd
}

func runPresetLint(out io.Writer, paths []string) error {
	failures := 0
	for _, path := range paths {
		if err := lintPresetFile(out, path); err != nil {
			failures++
			if _, werr := fmt.Fprintf(out, "%s %s: %v\n", ui.Colors.Red("✗"), path, err); werr != nil {
				return werr
			}
			continue
		}

		if _, err := fmt.Fprintf(out, "%s %s\n", ui.Colors.Green("✓"), path); err != nil {
			return err
		}
	}

	if failures > 0 {
		return invalidArgumentError(
			fmt.Sprintf("%d of %d preset file(s) failed validation", failures, len(paths)),
			"Fix the reported issues. See docs/sandbox-presets.md for the preset schema.",
		)
	}

	return nil
}

func lintPresetFile(_ io.Writer, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	preset, err := pmgsandbox.ParsePreset(data)
	if err != nil {
		return err
	}

	return preset.Validate()
}
