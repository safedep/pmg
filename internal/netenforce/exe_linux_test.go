//go:build linux

package netenforce

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestExePathChecksTheRecordedFile(t *testing.T) {
	var st unix.Stat_t
	require.NoError(t, unix.Stat("/proc/self/exe", &st))
	exe, err := os.Readlink("/proc/self/exe")
	require.NoError(t, err)
	pid := uint32(os.Getpid())

	assert.Equal(t, exe, exePath(pid, kernelDev(st.Dev), st.Ino))
	assert.Empty(t, exePath(pid, kernelDev(st.Dev), st.Ino+1), "another inode is another file")
	assert.Empty(t, exePath(pid, kernelDev(st.Dev)+1, st.Ino), "another device is another file")
	assert.Empty(t, exePath(pid, 0, 0), "a record without a file names none")
	assert.Empty(t, exePath(0, kernelDev(st.Dev), st.Ino), "a process outside the PID namespace")
}
