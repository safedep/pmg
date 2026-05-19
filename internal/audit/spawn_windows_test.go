//go:build windows

package audit

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestApplyDetachAttrsSetsCreationFlagsOnWindows(t *testing.T) {
	cmd := exec.Command("cmd.exe")
	applyDetachAttrs(cmd)

	require.NotNil(t, cmd.SysProcAttr, "applyDetachAttrs must populate SysProcAttr")
	want := uint32(windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP)
	assert.Equal(t, want, cmd.SysProcAttr.CreationFlags)
}
