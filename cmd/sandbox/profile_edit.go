package sandbox

import (
	"fmt"
	"io"

	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/editor"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

func newProfileEditCommand(factory registryFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "edit <name>",
		Short:         "Open a user sandbox profile in $VISUAL / $EDITOR and validate the result",
		Example:       "  pmg sandbox profile edit pnpm-custom",
		Args:          cobra.ExactArgs(1),
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runProfileEdit(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], factory)
			if err != nil {
				return sandboxErrorExit(cmd, err)
			}
			return err
		},
	}
	return cmd
}

func runProfileEdit(out, errOut io.Writer, name string, factory registryFactory) error {
	registry, err := factory()
	if err != nil {
		return registryInitError(err)
	}

	path, shadowed, err := findEditableUserProfile(registry, name)
	if err != nil {
		return err
	}

	if shadowed {
		if _, err := fmt.Fprintf(errOut,
			"Warning: user profile %q is shadowed by a built-in profile of the same name — pmg resolves the built-in, so edits here have no effect.\n",
			name); err != nil {
			return err
		}
	}

	if err := editor.Open(path); err != nil {
		return wrapUseful(err, errcodes.InvalidArgument,
			"Set $VISUAL or $EDITOR to a working editor command and retry.")
	}

	policy, err := registry.LoadCustomProfile(path)
	if err != nil {
		return profileLoadError(err)
	}

	issues := filterInfo(pmgsandbox.LintProfile(policy))
	return renderLintHuman(out, path, issues)
}

func findEditableUserProfile(registry pmgsandbox.ProfileRegistry, name string) (string, bool, error) {
	profiles, err := registry.ListUserProfiles()
	if err != nil {
		return "", false, wrapUseful(err, ioErrorCode(err, errcodes.Unknown),
			"Failed to enumerate user sandbox profiles. Check the user profile directory permissions.")
	}

	for _, p := range profiles {
		if p.Name == name {
			return p.Path, p.Shadowed, nil
		}
	}

	if _, ok := registry.BuiltinProfileYAML(name); ok {
		return "", false, invalidArgumentError(
			fmt.Sprintf("cannot edit built-in profile %q: built-in profiles are embedded in the pmg binary", name),
			fmt.Sprintf("Create an editable copy with `pmg sandbox profile init %s-custom --from %s`.", name, name),
		)
	}

	return "", false, notFoundError(
		fmt.Sprintf("no user sandbox profile named %q", name),
		"Use `pmg sandbox profile list` to see available profiles, or scaffold one with `pmg sandbox profile init`.",
	)
}
