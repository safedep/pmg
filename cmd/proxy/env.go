package proxy

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/safedep/pmg/internal/ui"
	"github.com/spf13/cobra"
)

var envExportFlag bool

func newEnvCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "env",
		Short: "Print proxy environment variables (KEY=VALUE per line)",
		Long: "Print proxy environment variables as KEY=VALUE lines.\n\n" +
			"GitHub Actions:  pmg proxy env >> \"$GITHUB_ENV\"\n" +
			"Shell:           eval \"$(pmg proxy env --export)\"\n\n" +
			"Use --export for shell `eval`: it emits quoted `export KEY='VALUE'`\n" +
			"lines that survive values containing spaces. The\n" +
			"default raw KEY=VALUE form is for $GITHUB_ENV, which must not be quoted.",
		RunE: runEnv,
	}
	cmd.Flags().BoolVar(&envExportFlag, "export", false, "Emit shell `export KEY='VALUE'` lines for `eval`")
	return cmd
}

func runEnv(_ *cobra.Command, _ []string) error {
	cfg := config.Get()
	statePath := proxyserver.ResolveStatePath(stateFlag, cfg.CacheDir())

	vars, err := proxyserver.EnvVars(statePath)
	if err != nil {
		ui.ErrorExit(err)
	}

	w := bufio.NewWriter(os.Stdout)
	for _, v := range vars {
		line := v
		if envExportFlag {
			line = exportLine(v)
		}
		if _, werr := fmt.Fprintln(w, line); werr != nil {
			ui.ErrorExit(fmt.Errorf("write env var: %w", werr))
		}
	}

	if err := w.Flush(); err != nil {
		ui.ErrorExit(err)
	}

	return nil
}

// exportLine turns "KEY=VALUE" into a shell-safe `export KEY='VALUE'`, so values
// with spaces (e.g. the macOS "Application Support" path) survive `eval`.
func exportLine(kv string) string {
	k, v, ok := strings.Cut(kv, "=")
	if !ok {
		return kv
	}
	return fmt.Sprintf("export %s=%s", k, shellSingleQuote(v))
}

// shellSingleQuote wraps s in single quotes, escaping any embedded single quote
// as '\” (close, escaped quote, reopen).
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
