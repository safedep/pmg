package proxy

import (
	"bufio"
	"fmt"
	"os"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/safedep/pmg/internal/ui"
	"github.com/spf13/cobra"
)

func newEnvCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "env",
		Short: "Print proxy environment variables (KEY=VALUE per line)",
		Long: "Print proxy environment variables as KEY=VALUE lines.\n\n" +
			"GitHub Actions:  pmg proxy env >> \"$GITHUB_ENV\"\n" +
			"Shell:           export $(pmg proxy env | xargs)",
		RunE: runEnv,
	}
}

func runEnv(_ *cobra.Command, _ []string) error {
	cfg := config.Get()
	statePath := proxyserver.ResolveStatePath(stateFlag, cfg)

	vars, err := proxyserver.EnvVars(cfg, statePath)
	if err != nil {
		ui.ErrorExit(err)
	}

	w := bufio.NewWriter(os.Stdout)
	for _, v := range vars {
		if _, werr := fmt.Fprintln(w, v); werr != nil {
			ui.ErrorExit(fmt.Errorf("write env var: %w", werr))
		}
	}

	if err := w.Flush(); err != nil {
		ui.ErrorExit(err)
	}

	return nil
}
