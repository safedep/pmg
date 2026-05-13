package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
