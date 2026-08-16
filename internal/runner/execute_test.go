package runner

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/shim"
	"github.com/safedep/pmg/packagemanager"
	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeEnvOverridesExistingValues(t *testing.T) {
	env := mergeEnv(
		[]string{
			"PATH=/usr/bin",
			"HTTP_PROXY=http://old-proxy",
			"NO_PROXY=localhost",
		},
		[]string{
			"HTTP_PROXY=http://pmg-proxy",
			"HTTPS_PROXY=http://pmg-proxy",
			"NO_PROXY=localhost,127.0.0.1",
		},
	)

	assert.Equal(t, []string{
		"PATH=/usr/bin",
		"HTTP_PROXY=http://pmg-proxy",
		"NO_PROXY=localhost,127.0.0.1",
		"HTTPS_PROXY=http://pmg-proxy",
	}, env)
}

func TestModeEnvOverrides(t *testing.T) {
	opts := ExecuteOptions{
		EnvOverrides:       []string{"HTTP_PROXY=http://pmg-proxy"},
		DirectEnvOverrides: []string{"CI=true"},
		PTYEnvOverrides:    []string{"TERM=xterm-256color"},
	}

	assert.Equal(t,
		[]string{"HTTP_PROXY=http://pmg-proxy", "CI=true"},
		modeEnvOverrides(opts, ExecutionModeDirect),
	)

	assert.Equal(t,
		[]string{"HTTP_PROXY=http://pmg-proxy", "TERM=xterm-256color"},
		modeEnvOverrides(opts, ExecutionModePTY),
	)
}

func TestExecutionModeAuto(t *testing.T) {
	assert.Equal(t, ExecutionModePTY, executionMode(ExecuteOptions{
		Mode:          ExecutionModeAuto,
		IsInteractive: func() bool { return true },
	}))

	assert.Equal(t, ExecutionModeDirect, executionMode(ExecuteOptions{
		Mode:          ExecutionModeAuto,
		IsInteractive: func() bool { return false },
	}))
}

func TestExecuteWithOptionsRunsDirectHookBeforeSandbox(t *testing.T) {
	cfg := config.Get()
	previous := *cfg
	t.Cleanup(func() {
		*cfg = previous
	})

	cfg.Config.Sandbox.Enabled = true
	cfg.Config.Sandbox.Policies = map[string]config.SandboxPolicyRef{}

	exe, err := os.Executable()
	require.NoError(t, err)

	hookCalled := false
	err = ExecuteWithOptions(context.Background(), &packagemanager.ParsedCommand{
		Command: packagemanager.Command{
			Exe: exe,
		},
	}, ExecuteOptions{
		PackageManagerName: "npm",
		Mode:               ExecutionModeDirect,
		BeforeDirectRun: func() error {
			hookCalled = true
			return nil
		},
	})

	require.Error(t, err)
	assert.True(t, hookCalled)
}

func TestExecuteWithOptionsMissingPackageManager(t *testing.T) {
	tmpDir := t.TempDir()
	pmgBin := filepath.Join(tmpDir, ".pmg", "bin")
	require.NoError(t, os.MkdirAll(pmgBin, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pmgBin, "bun"), []byte("#!/bin/sh\necho shim"), 0o755))

	t.Setenv("PATH", pmgBin)

	err := ExecuteWithOptions(context.Background(), &packagemanager.ParsedCommand{
		Command: packagemanager.Command{
			Exe:  "bun",
			Args: []string{"--version"},
		},
	}, ExecuteOptions{
		PackageManagerName: "bun",
	})

	var notFound *shim.BinaryNotFoundError
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, "bun", notFound.Name)
	assert.Equal(t, 127, notFound.ExitCode())
}

type stubDiagnosticsSandbox struct {
	sandbox.Sandbox
	writer io.Writer
}

func (s stubDiagnosticsSandbox) DiagnosticsWriter() io.Writer { return s.writer }

func TestPTYOutputTeesToSandboxDiagnostics(t *testing.T) {
	var tap bytes.Buffer

	result := sandbox.NewExecutionResult(
		sandbox.WithExecutionResultSandbox(stubDiagnosticsSandbox{writer: &tap}))

	_, err := ptyOutput(result).Write([]byte("cat: /work/.env: Permission denied\n"))
	require.NoError(t, err)

	assert.Equal(t, "cat: /work/.env: Permission denied\n", tap.String())
}

func TestPTYOutputIsStdoutWithoutDiagnostics(t *testing.T) {
	assert.Equal(t, os.Stdout, ptyOutput(sandbox.NewExecutionResult()))
}
