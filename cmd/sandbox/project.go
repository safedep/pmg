package sandbox

import (
	"os"

	"github.com/safedep/pmg/config"
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
