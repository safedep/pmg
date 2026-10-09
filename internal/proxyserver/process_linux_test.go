//go:build linux

package proxyserver

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessRunningSeesSelf(t *testing.T) {
	comm, err := os.ReadFile("/proc/self/comm")
	require.NoError(t, err)
	assert.True(t, processRunning(strings.TrimSpace(string(comm))))
	assert.False(t, processRunning("pmg-no-such-process"))
}
