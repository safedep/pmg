package sandbox

import (
	"fmt"
	"io"

	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/editor"
	"github.com/safedep/pmg/internal/ui"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

func newPresetEditCommand(factory presetRegistryFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "edit <name>",
		Short:         "Open a user sandbox preset in $VISUAL / $EDITOR and validate the result",
		Example:       "  pmg sandbox preset edit myapp",
		Args:          cobra.ExactArgs(1),
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPresetEdit(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], factory); err != nil {
				return sandboxErrorExit(cmd, err)
			}
			return nil
		},
	}
	return cmd
}

func runPresetEdit(out, errOut io.Writer, name string, factory presetRegistryFactory) error {
	registry, err := factory()
	if err != nil {
		return presetRegistryError(err)
	}

	path, shadowed, err := findEditableUserPreset(registry, name)
	if err != nil {
		return err
	}

	if shadowed {
		if _, err := fmt.Fprintf(errOut,
			"Warning: user preset %q is shadowed by a built-in preset of the same name — pmg resolves the built-in, so edits here have no effect.\n",
			name); err != nil {
			return err
		}
	}

	if err := editor.Open(path); err != nil {
		return wrapUseful(err, errcodes.InvalidArgument,
			"Set $VISUAL or $EDITOR to a working editor command and retry.")
	}

	if err := lintPresetFile(out, path); err != nil {
		return wrapUseful(err, errcodes.InvalidArgument,
			"The edited preset is invalid and will be skipped at load time. Fix the reported issue in "+path+".")
	}

	_, err = fmt.Fprintf(out, "%s %s\n", ui.Colors.Green("✓"), path)
	return err
}

func findEditableUserPreset(registry pmgsandbox.PresetRegistry, name string) (string, bool, error) {
	infos, err := registry.List()
	if err != nil {
		return "", false, presetRegistryError(err)
	}

	for _, info := range infos {
		if info.Preset.Name == name && info.Source == pmgsandbox.PresetSourceUser {
			return info.Path, info.Shadowed, nil
		}
	}

	for _, info := range infos {
		if info.Preset.Name == name && info.Source == pmgsandbox.PresetSourceBuiltin {
			return "", false, invalidArgumentError(
				fmt.Sprintf("cannot edit built-in preset %q: built-in presets are embedded in the pmg binary", name),
				fmt.Sprintf("Scaffold your own with `pmg sandbox preset init %s-custom`.", name),
			)
		}
	}

	return "", false, notFoundError(
		fmt.Sprintf("no user sandbox preset named %q", name),
		"Use `pmg sandbox preset list` to see available presets, or scaffold one with `pmg sandbox preset init`.",
	)
}
