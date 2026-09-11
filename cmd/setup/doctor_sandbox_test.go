package setup

import (
	"context"
	"errors"
	"os/exec"
	"testing"

	"github.com/safedep/pmg/internal/doctor"
	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
)

type fakeDoctorSandbox struct{ available bool }

func (f fakeDoctorSandbox) Execute(context.Context, *exec.Cmd, *sandbox.SandboxPolicy, *sandbox.ExecutionContext) (*sandbox.ExecutionResult, error) {
	return sandbox.NewExecutionResult(), nil
}
func (f fakeDoctorSandbox) Name() sandbox.DriverName { return "fake" }
func (f fakeDoctorSandbox) IsAvailable() bool        { return f.available }
func (f fakeDoctorSandbox) Close() error             { return nil }

// An OS with no sandbox has nothing to enable, so a disabled sandbox
// passes there and carries no fix. Only a config that asks for one fails.
func TestEvaluateSandboxCheck(t *testing.T) {
	noSandbox := errors.New("PMG has no sandbox on Windows")
	tests := []struct {
		name        string
		sb          sandbox.Sandbox
		platformErr error
		enabled     bool
		status      doctor.CheckStatus
		message     string
		fix         string
	}{
		{"no sandbox on this OS, disabled", nil, noSandbox, false, doctor.StatusPass, "PMG has no sandbox on", ""},
		{"no sandbox on this OS, enabled", nil, noSandbox, true, doctor.StatusFail, "Sandbox is enabled, but PMG has no sandbox on", "Set sandbox.enabled: false in config"},
		{"driver present, disabled", fakeDoctorSandbox{available: true}, nil, false, doctor.StatusWarn, "Sandbox is disabled", ""},
		{"driver missing, enabled", fakeDoctorSandbox{available: false}, nil, true, doctor.StatusFail, "no driver available", ""},
		{"driver present, enabled", fakeDoctorSandbox{available: true}, nil, true, doctor.StatusPass, "Sandbox enabled (fake)", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateSandboxCheck(tt.sb, tt.platformErr, tt.enabled)
			assert.Equal(t, tt.status, got.Status)
			assert.Contains(t, got.Message, tt.message)
			assert.Equal(t, tt.fix, got.Fix)
		})
	}
}
