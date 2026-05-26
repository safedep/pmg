package sandbox

import (
	"fmt"
	"io"
	"os"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/ui"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

// projectDeps is the dependency surface for `pmg sandbox project` subcommands.
type projectDeps struct {
	overlayDir func() string
	repoRoot   func() (string, error)
}

func defaultProjectDeps() projectDeps {
	return projectDeps{
		overlayDir: func() string { return config.Get().SandboxOverlayDir() },
		repoRoot:   resolveCurrentRepoRoot,
	}
}

// resolveCurrentRepoRoot returns the git toplevel for the current working
// directory, falling back to the cwd itself when not inside a git work tree.
func resolveCurrentRepoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return pmgsandbox.ResolveRepoRoot(cwd)
}

// renderProjectSection prints the standard PMG section header
// (blank line, cyan title, dashed separator).
func renderProjectSection(out io.Writer, title string) error {
	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, ui.Colors.Cyan(title)); err != nil {
		return err
	}
	_, err := fmt.Fprintln(out, ui.Colors.Normal("--------------------"))
	return err
}

// renderKeyValueBlock prints aligned "Key: value" pairs with bold keys. Empty
// values are skipped so optional fields do not produce empty lines.
func renderKeyValueBlock(out io.Writer, entries [][2]string) error {
	width := 0
	for _, e := range entries {
		if e[1] != "" && len(e[0]) > width {
			width = len(e[0])
		}
	}
	for _, e := range entries {
		if e[1] == "" {
			continue
		}
		label := fmt.Sprintf("%-*s", width+1, e[0]+":")
		if _, err := fmt.Fprintf(out, "%s  %s\n", ui.Colors.Bold(label), e[1]); err != nil {
			return err
		}
	}
	return nil
}

// NewProjectCommand returns the `pmg sandbox project` parent command.
func NewProjectCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "project",
		Short: "Inspect and manage the current repository's sandbox overlay",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	deps := defaultProjectDeps()
	cmd.AddCommand(newProjectShowCommand(deps))
	cmd.AddCommand(newProjectResetCommand(deps))
	cmd.AddCommand(newProjectListCommand(deps))
	return cmd
}
