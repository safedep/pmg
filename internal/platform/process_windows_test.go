package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The test binary starts itself as a child. The child reports its parent,
// which is this binary, by file name.
func TestParentProcessName(t *testing.T) {
	if os.Getenv("PMG_PARENT_PROCESS_CHILD") == "1" {
		name, err := ParentProcessName()
		if err != nil {
			t.Fatalf("parent process name: %v", err)
		}
		_, _ = os.Stdout.WriteString(name)
		return
	}

	self, err := os.Executable()
	require.NoError(t, err)
	child := exec.Command(self, "-test.run=^TestParentProcessName$")
	child.Env = append(os.Environ(), "PMG_PARENT_PROCESS_CHILD=1")
	output, err := child.Output()
	require.NoError(t, err, string(output))

	reported := strings.TrimSpace(strings.Split(string(output), "\n")[0])
	assert.Equal(t, strings.ToLower(filepath.Base(self)), strings.ToLower(reported))
}
