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

type projectShowOptions struct {
	jsonOut bool
}

func newProjectShowCommand(deps projectDeps) *cobra.Command {
	opts := &projectShowOptions{}

	cmd := &cobra.Command{
		Use:           "show",
		Short:         "Show the saved sandbox overlay for the current repository",
		SilenceErrors: false,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runProjectShow(cmd.OutOrStdout(), opts, deps); err != nil {
				return sandboxErrorExit(cmd, err)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&opts.jsonOut, "json", false, "Emit overlay as JSON")
	return cmd
}

type projectShowJSONAllow struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type projectShowJSONPayload struct {
	RepoRoot  string                 `json:"repo_root"`
	Path      string                 `json:"path,omitempty"`
	UpdatedAt string                 `json:"updated_at,omitempty"`
	Allow     []projectShowJSONAllow `json:"allow"`
}

func runProjectShow(out io.Writer, opts *projectShowOptions, deps projectDeps) error {
	repoRoot, err := deps.repoRoot()
	if err != nil {
		return wrapUseful(err, errcodes.Unknown, "Could not determine the current repository root.")
	}
	overlay, path, err := pmgsandbox.LoadOverlayForRepo(deps.overlayDir(), repoRoot)
	if err != nil {
		return wrapUseful(err, errcodes.Unknown, "Could not read the project overlay file.")
	}

	if opts.jsonOut {
		payload := projectShowJSONPayload{RepoRoot: repoRoot, Path: path, Allow: []projectShowJSONAllow{}}
		if overlay != nil {
			for _, a := range overlay.Allow {
				payload.Allow = append(payload.Allow, projectShowJSONAllow{Type: string(a.Type), Value: a.Value})
			}
			if !overlay.UpdatedAt.IsZero() {
				payload.UpdatedAt = overlay.UpdatedAt.UTC().Format(time.RFC3339)
			}
		}
		return writeJSONIndent(out, payload)
	}

	if err := renderProjectSection(out, "Project Overlay"); err != nil {
		return err
	}

	if overlay == nil || len(overlay.Allow) == 0 {
		_, err := fmt.Fprintf(out, "%s\n", ui.Colors.Dim(fmt.Sprintf("No project overlay for %s", repoRoot)))
		return err
	}

	updated := ""
	if !overlay.UpdatedAt.IsZero() {
		updated = overlay.UpdatedAt.UTC().Format(time.RFC3339)
	}
	if err := renderKeyValueBlock(out, [][2]string{
		{"Repo", repoRoot},
		{"Overlay", path},
		{"Updated", updated},
	}); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}

	rows := make([][]string, 0, len(overlay.Allow)+1)
	rows = append(rows, []string{
		ui.Colors.Bold("TYPE"),
		ui.Colors.Bold("VALUE"),
	})
	for _, a := range overlay.Allow {
		rows = append(rows, []string{string(a.Type), a.Value})
	}
	return renderTable(out, rows, nil)
}
