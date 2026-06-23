package proxy

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/proxystate"
	"github.com/spf13/cobra"
)

func newEnvCommand() *cobra.Command {
	var gha bool

	cmd := &cobra.Command{
		Use:   "env",
		Short: "Print proxy environment variables (use with eval or --gha for GitHub Actions)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runEnv(gha)
		},
	}

	cmd.Flags().BoolVar(&gha, "gha", false, "Write env vars to $GITHUB_ENV instead of stdout")
	return cmd
}

func runEnv(gha bool) error {
	cfg := config.Get()
	statePath := proxystate.StatePath(cfg.ConfigDir())

	state, err := proxystate.Read(statePath)
	if err != nil {
		return fmt.Errorf("proxy not running — start with 'pmg proxy start' first: %w", err)
	}

	proxyURL := fmt.Sprintf("http://%s", state.Addr)
	noProxy := "localhost,127.0.0.1,::1"

	vars := []string{
		fmt.Sprintf("HTTP_PROXY=%s", proxyURL),
		fmt.Sprintf("HTTPS_PROXY=%s", proxyURL),
		fmt.Sprintf("http_proxy=%s", proxyURL),
		fmt.Sprintf("https_proxy=%s", proxyURL),
		fmt.Sprintf("NO_PROXY=%s", noProxy),
		fmt.Sprintf("no_proxy=%s", noProxy),
		"NODE_USE_ENV_PROXY=1",
		fmt.Sprintf("NODE_EXTRA_CA_CERTS=%s", state.CACertPath),
		fmt.Sprintf("SSL_CERT_FILE=%s", state.CACertPath),
		fmt.Sprintf("REQUESTS_CA_BUNDLE=%s", state.CACertPath),
		fmt.Sprintf("PIP_CERT=%s", state.CACertPath),
		fmt.Sprintf("PIP_PROXY=%s", proxyURL),
		"PIP_RETRIES=0",
		fmt.Sprintf("YARN_HTTP_PROXY=%s", proxyURL),
		fmt.Sprintf("YARN_HTTPS_PROXY=%s", proxyURL),
		fmt.Sprintf("YARN_HTTPS_CA_FILE_PATH=%s", state.CACertPath),
	}

	if gha {
		return writeGitHubEnv(vars)
	}

	return writeShellExports(vars)
}

func writeShellExports(vars []string) error {
	w := bufio.NewWriter(os.Stdout)
	for _, kv := range vars {
		// Split on first '=' so we can quote only the value, handling paths with spaces.
		k, v, _ := strings.Cut(kv, "=")
		if _, err := fmt.Fprintf(w, "export %s=%q\n", k, v); err != nil {
			return fmt.Errorf("write env var: %w", err)
		}
	}
	return w.Flush()
}

func writeGitHubEnv(vars []string) error {
	ghEnvFile := os.Getenv("GITHUB_ENV")
	if ghEnvFile == "" {
		return fmt.Errorf("$GITHUB_ENV is not set — are you running in GitHub Actions?")
	}

	f, err := os.OpenFile(ghEnvFile, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open $GITHUB_ENV file: %w", err)
	}
	defer func() {
		_ = f.Close()
	}()

	w := bufio.NewWriter(f)
	for _, v := range vars {
		if _, err := fmt.Fprintf(w, "%s\n", v); err != nil {
			return fmt.Errorf("write to $GITHUB_ENV: %w", err)
		}
	}
	return w.Flush()
}
