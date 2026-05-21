//go:build !windows

package audit

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyDetachAttrsSetsSetsidOnUnix(t *testing.T) {
	cmd := exec.Command("true")
	applyDetachAttrs(cmd)

	require.NotNil(t, cmd.SysProcAttr, "applyDetachAttrs must populate SysProcAttr")
	assert.True(t, cmd.SysProcAttr.Setsid, "Unix detach must set Setsid so child becomes a new session leader")
}
