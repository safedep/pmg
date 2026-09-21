//go:build linux

package platform

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestReadLandlockPolicyFromFile(t *testing.T) {
	policy := &landlockExecPolicy{
		Command: "/usr/bin/node",
		Args:    []string{"index.js"},
		Env:     []string{"HOME=/home/user", "PATH=/usr/bin"},
		FilesystemRules: []landlockPathRule{
			{Path: "/usr", Access: 0x0C},
			{Path: "/tmp", Access: 0xFF},
		},
		DenyPaths: []denyPathEntry{
			{Path: "/home/user/.ssh/", Mode: denyBoth},
		},
		DenyExecPaths:    []string{"/usr/bin/curl"},
		AllowPTY:         true,
		SkipPIDNamespace: false,
		SkipIPCNamespace: false,
	}

	// Write policy to temp file
	f, err := os.CreateTemp("", "pmg-test-policy-*.json")
	require.NoError(t, err)
	defer func() {
		if err := os.Remove(f.Name()); err != nil {
			t.Logf("remove temp policy: %v", err)
		}
	}()

	err = json.NewEncoder(f).Encode(policy)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	got, err := readLandlockPolicyFromFile(f.Name())
	require.NoError(t, err)

	assert.Equal(t, "/usr/bin/node", got.Command)
	assert.Equal(t, []string{"index.js"}, got.Args)
	assert.Equal(t, []string{"HOME=/home/user", "PATH=/usr/bin"}, got.Env)
	assert.Len(t, got.FilesystemRules, 2)
	assert.Equal(t, "/usr", got.FilesystemRules[0].Path)
	assert.Equal(t, uint64(0x0C), got.FilesystemRules[0].Access)
	assert.Len(t, got.DenyPaths, 1)
	assert.Equal(t, "/home/user/.ssh/", got.DenyPaths[0].Path)
	assert.Equal(t, denyBoth, got.DenyPaths[0].Mode)
	assert.Equal(t, []string{"/usr/bin/curl"}, got.DenyExecPaths)
	assert.True(t, got.AllowPTY)
	assert.False(t, got.SkipPIDNamespace)
	assert.False(t, got.SkipIPCNamespace)
}

func TestReadLandlockPolicyFromFile_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "invalid JSON",
			input: `{this is not json}`,
		},
		{
			name:  "empty command",
			input: `{"command":"","args":[]}`,
		},
		{
			name:  "empty input",
			input: ``,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.CreateTemp("", "pmg-test-policy-*.json")
			require.NoError(t, err)
			defer func() {
				if err := os.Remove(f.Name()); err != nil {
					t.Logf("remove temp policy: %v", err)
				}
			}()

			_, err = f.WriteString(tt.input)
			require.NoError(t, err)
			require.NoError(t, f.Close())

			_, err = readLandlockPolicyFromFile(f.Name())
			assert.Error(t, err)
		})
	}
}

func TestReadLandlockPolicyFromFile_EmptyPath(t *testing.T) {
	_, err := readLandlockPolicyFromFile("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "policy file path is empty")
}

func TestReadLandlockPolicyFromFile_NonexistentFile(t *testing.T) {
	_, err := readLandlockPolicyFromFile("/tmp/nonexistent-policy-file-12345.json")
	assert.Error(t, err)
}

func TestLandlockBuildCloneflags_Default(t *testing.T) {
	policy := &landlockExecPolicy{
		Command:          "/bin/sh",
		SkipPIDNamespace: false,
		SkipIPCNamespace: false,
	}

	flags := landlockBuildCloneflags(policy)

	expected := uintptr(unix.CLONE_NEWPID | unix.CLONE_NEWIPC | unix.CLONE_NEWNS)
	assert.Equal(t, expected, flags)
}

func TestLandlockBuildCloneflags_SkipPID(t *testing.T) {
	policy := &landlockExecPolicy{
		Command:          "/bin/sh",
		SkipPIDNamespace: true,
		SkipIPCNamespace: false,
	}

	flags := landlockBuildCloneflags(policy)

	expected := uintptr(unix.CLONE_NEWIPC)
	assert.Equal(t, expected, flags)
}

func TestLandlockBuildCloneflags_SkipIPC(t *testing.T) {
	policy := &landlockExecPolicy{
		Command:          "/bin/sh",
		SkipPIDNamespace: false,
		SkipIPCNamespace: true,
	}

	flags := landlockBuildCloneflags(policy)

	expected := uintptr(unix.CLONE_NEWPID | unix.CLONE_NEWNS)
	assert.Equal(t, expected, flags)
}

func TestLandlockBuildCloneflags_SkipBoth(t *testing.T) {
	policy := &landlockExecPolicy{
		Command:          "/bin/sh",
		SkipPIDNamespace: true,
		SkipIPCNamespace: true,
	}

	flags := landlockBuildCloneflags(policy)

	assert.Equal(t, uintptr(0), flags)
}

func TestUnmappedID(t *testing.T) {
	t.Run("overflow differs", func(t *testing.T) {
		id, err := unmappedID(writeOverflowFile(t, "65534"))
		require.NoError(t, err)
		assert.Equal(t, preferredUnmappedID, id)
	})

	t.Run("overflow collides", func(t *testing.T) {
		id, err := unmappedID(writeOverflowFile(t, "65533"))
		require.NoError(t, err)
		assert.Equal(t, preferredUnmappedID-1, id)
	})

	t.Run("unreadable value fails closed", func(t *testing.T) {
		_, err := unmappedID(writeOverflowFile(t, "garbage"))
		require.Error(t, err)
	})

	t.Run("missing file fails closed", func(t *testing.T) {
		_, err := unmappedID("/nonexistent")
		require.Error(t, err)
	})
}

func writeOverflowFile(t *testing.T, value string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "overflowuid")
	require.NoError(t, os.WriteFile(p, []byte(value+"\n"), 0o644))
	return p
}
