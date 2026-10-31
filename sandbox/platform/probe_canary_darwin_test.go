//go:build darwin
// +build darwin

package platform

import (
	"context"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/pmg/sandbox"
)

// The real driver, the real translator and the real sandbox-exec. A canary
// that cannot start, for example because the profile denies its libraries,
// must not pass as a blocked read.
func TestSeatbeltCanaryBlocksRead(t *testing.T) {
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not found")
	}
	res := NewSeatbeltCanaryProbe().Run(context.Background())
	assert.Equal(t, sandbox.ProbeStatusOK, res.Status, "%s: %s", res.Summary, res.Detail)
}
