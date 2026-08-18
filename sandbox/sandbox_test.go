package sandbox

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubSandbox struct{}

func (stubSandbox) Execute(context.Context, *exec.Cmd, *SandboxPolicy, *ExecutionContext) (*ExecutionResult, error) {
	return nil, nil
}
func (stubSandbox) Name() DriverName  { return "stub" }
func (stubSandbox) IsAvailable() bool { return true }
func (stubSandbox) Close() error      { return nil }

type stubDiagnosticsSandbox struct {
	stubSandbox
	writer io.Writer
}

func (s stubDiagnosticsSandbox) DiagnosticsWriter() io.Writer { return s.writer }

func TestExecutionResultScrubbedEnvCount(t *testing.T) {
	r := NewExecutionResult()
	assert.Equal(t, 0, r.ScrubbedEnvCount())

	r.SetScrubbedEnvCount(3)
	assert.Equal(t, 3, r.ScrubbedEnvCount())
}

func TestExecutionResultScrubbedEnvCountNilReceiver(t *testing.T) {
	var r *ExecutionResult
	assert.Equal(t, 0, r.ScrubbedEnvCount())
}

func TestExecutionResultDiagnosticsWriter(t *testing.T) {
	var sink bytes.Buffer

	tests := []struct {
		name   string
		result *ExecutionResult
		want   io.Writer
	}{
		{
			name:   "nil result",
			result: nil,
		},
		{
			name:   "no sandbox",
			result: NewExecutionResult(),
		},
		{
			name:   "driver without diagnostics",
			result: NewExecutionResult(WithExecutionResultSandbox(stubSandbox{})),
		},
		{
			name:   "driver with diagnostics",
			result: NewExecutionResult(WithExecutionResultSandbox(stubDiagnosticsSandbox{writer: &sink})),
			want:   &sink,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.result.DiagnosticsWriter())
		})
	}
}

func TestExecutionResultDiagnosticsWriterNilWhenDriverHasNoTap(t *testing.T) {
	result := NewExecutionResult(WithExecutionResultSandbox(stubDiagnosticsSandbox{}))

	// A driver that has not run yet must report no writer, so that callers never
	// pass a nil into io.MultiWriter.
	require.Nil(t, result.DiagnosticsWriter())
}
