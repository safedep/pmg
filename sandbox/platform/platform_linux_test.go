//go:build linux

package platform

import (
	"context"
	"errors"
	"os/exec"
	"testing"

	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testSandbox struct {
	name      string
	available bool
}

func (s *testSandbox) Name() string {
	return s.name
}

func (s *testSandbox) IsAvailable() bool {
	return s.available
}

func (s *testSandbox) Execute(context.Context, *exec.Cmd, *sandbox.SandboxPolicy) (*sandbox.ExecutionResult, error) {
	return sandbox.NewExecutionResult(sandbox.WithExecutionResultSandbox(s)), nil
}

func (s *testSandbox) Close() error {
	return nil
}

func TestNewSandbox_DefaultFallsBackToBubblewrapWhenLandlockUnavailable(t *testing.T) {
	restoreFactories := replaceSandboxFactories(t,
		func() (sandbox.Sandbox, error) {
			return nil, errors.New("landlock shim not available")
		},
		func() (sandbox.Sandbox, error) {
			return &testSandbox{name: "bubblewrap", available: true}, nil
		},
	)
	defer restoreFactories()
	t.Setenv("PMG_SANDBOX_DRIVER", "")

	sb, err := NewSandbox()
	require.NoError(t, err)
	assert.Equal(t, "bubblewrap", sb.Name())
}

func TestNewSandbox_DefaultUsesLandlockWhenAvailable(t *testing.T) {
	restoreFactories := replaceSandboxFactories(t,
		func() (sandbox.Sandbox, error) {
			return &testSandbox{name: "landlock", available: true}, nil
		},
		func() (sandbox.Sandbox, error) {
			return nil, errors.New("bubblewrap should not be used")
		},
	)
	defer restoreFactories()
	t.Setenv("PMG_SANDBOX_DRIVER", "")

	sb, err := NewSandbox()
	require.NoError(t, err)
	assert.Equal(t, "landlock", sb.Name())
}

func TestNewSandbox_ForcedLandlockDoesNotFallback(t *testing.T) {
	bubblewrapCalled := false
	restoreFactories := replaceSandboxFactories(t,
		func() (sandbox.Sandbox, error) {
			return nil, errors.New("landlock shim not available")
		},
		func() (sandbox.Sandbox, error) {
			bubblewrapCalled = true
			return &testSandbox{name: "bubblewrap", available: true}, nil
		},
	)
	defer restoreFactories()
	t.Setenv("PMG_SANDBOX_DRIVER", "landlock")

	sb, err := NewSandbox()
	require.Error(t, err)
	assert.Nil(t, sb)
	assert.False(t, bubblewrapCalled)
}

func TestNewSandbox_ForcedBubblewrapSkipsLandlock(t *testing.T) {
	landlockCalled := false
	restoreFactories := replaceSandboxFactories(t,
		func() (sandbox.Sandbox, error) {
			landlockCalled = true
			return &testSandbox{name: "landlock", available: true}, nil
		},
		func() (sandbox.Sandbox, error) {
			return &testSandbox{name: "bubblewrap", available: true}, nil
		},
	)
	defer restoreFactories()
	t.Setenv("PMG_SANDBOX_DRIVER", "bubblewrap")

	sb, err := NewSandbox()
	require.NoError(t, err)
	assert.Equal(t, "bubblewrap", sb.Name())
	assert.False(t, landlockCalled)
}

func replaceSandboxFactories(
	t *testing.T,
	landlockFactory func() (sandbox.Sandbox, error),
	bubblewrapFactory func() (sandbox.Sandbox, error),
) func() {
	t.Helper()

	origLandlock := landlockSandboxFactory
	origBubblewrap := bubblewrapSandboxFactory
	landlockSandboxFactory = landlockFactory
	bubblewrapSandboxFactory = bubblewrapFactory

	return func() {
		landlockSandboxFactory = origLandlock
		bubblewrapSandboxFactory = origBubblewrap
	}
}
