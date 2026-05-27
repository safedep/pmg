package sandbox

import (
	"fmt"
	"io"
	"time"

	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/ui"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

type projectListOptions struct {
	jsonOut bool
}

func newProjectListCommand(deps projectDeps) *cobra.Command {
	opts := &projectListOptions{}

	cmd := &cobra.Command{
		Use:           "list",
		Short:         "List all known sandbox project overlays",
		Args:          cobra.NoArgs,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runProjectList(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts, deps); err != nil {
				return sandboxErrorExit(cmd, err)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&opts.jsonOut, "json", false, "Emit entries as JSON")
	return cmd
}

type projectListJSONEntry struct {
	RepoRoot  string `json:"repo_root"`
	Entries   int    `json:"entries"`
	Path      string `json:"path"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type projectListJSONOutput struct {
	Entries []projectListJSONEntry `json:"entries"`
}

func runProjectList(out, _ io.Writer, opts *projectListOptions, deps projectDeps) error {
	overlays, err := pmgsandbox.ListOverlays(deps.overlayDir())
	if err != nil {
		return wrapUseful(err, errcodes.Unknown, "Could not list project overlays.")
	}

	if opts.jsonOut {
		payload := projectListJSONOutput{Entries: make([]projectListJSONEntry, 0, len(overlays))}
		for _, e := range overlays {
			item := projectListJSONEntry{
				RepoRoot: e.Overlay.RepoRoot,
				Entries:  len(e.Overlay.Allow),
				Path:     e.Path,
			}
			if !e.Overlay.UpdatedAt.IsZero() {
				item.UpdatedAt = e.Overlay.UpdatedAt.UTC().Format(time.RFC3339)
			}
			payload.Entries = append(payload.Entries, item)
		}
		return writeJSONIndent(out, payload)
	}

	if err := renderProjectSection(out, "Project Overlays"); err != nil {
		return err
	}

	if len(overlays) == 0 {
		_, err := fmt.Fprintln(out, ui.Colors.Dim("No project overlays."))
		return err
	}

	rows := [][]string{{
		ui.Colors.Bold("REPO"),
		ui.Colors.Bold("ENTRIES"),
		ui.Colors.Bold("UPDATED"),
	}}
	dash := ui.Colors.Dim("—")
	for _, e := range overlays {
		updated := dash
		if !e.Overlay.UpdatedAt.IsZero() {
			updated = e.Overlay.UpdatedAt.UTC().Format(time.RFC3339)
		}
		rows = append(rows, []string{e.Overlay.RepoRoot, fmt.Sprintf("%d", len(e.Overlay.Allow)), updated})
	}
	return renderTable(out, rows, nil)
}
