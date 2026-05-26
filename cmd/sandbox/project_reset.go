package sandbox

import (
	"fmt"
	"io"

	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/ui"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

type projectResetOptions struct {
	yes bool
}

func newProjectResetCommand(deps projectDeps) *cobra.Command {
	opts := &projectResetOptions{}

	cmd := &cobra.Command{
		Use:           "reset",
		Short:         "Delete the sandbox overlay for the current repository",
		Args:          cobra.NoArgs,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runProjectReset(cmd.OutOrStdout(), opts, deps); err != nil {
				return sandboxErrorExit(cmd, err)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&opts.yes, "yes", false, "Confirm deletion without an interactive prompt")
	return cmd
}

func runProjectReset(out io.Writer, opts *projectResetOptions, deps projectDeps) error {
	if !opts.yes {
		return invalidArgumentError(
			"refusing to reset without --yes",
			"Re-run with `pmg sandbox project reset --yes` to delete the overlay.",
		)
	}

	repoRoot, err := deps.repoRoot()
	if err != nil {
		return wrapUseful(err, errcodes.Unknown, "Could not determine the current repository root.")
	}
	overlay, path, err := pmgsandbox.LoadOverlayForRepo(deps.overlayDir(), repoRoot)
	if err != nil {
		return wrapUseful(err, errcodes.Unknown, "Could not read the project overlay file.")
	}
	if overlay == nil {
		_, err := fmt.Fprintf(out, "%s\n", ui.Colors.Dim(fmt.Sprintf("No project overlay for %s", repoRoot)))
		return err
	}
	if err := pmgsandbox.DeleteOverlayForRepo(deps.overlayDir(), repoRoot); err != nil {
		return wrapUseful(err, errcodes.Unknown, "Could not delete the project overlay file.")
	}
	if _, err := fmt.Fprintf(out, "%s Deleted overlay for %s\n", ui.Colors.Green("✓"), repoRoot); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "  %s\n", ui.Colors.Dim(path))
	return err
}
