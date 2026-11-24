package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pmg starts a background cloud sync when a command exits with cloud on, also
// after --help. When policy.sh probed for --require-policy with cloud on, that
// sync held the sync lock, and the policy fetch that followed failed with
// "Another cloud sync is already in progress".
func TestPolicyScriptProbesHelpWithCloudOff(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the action runs only on Linux")
	}

	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	fakePMG := filepath.Join(dir, "pmg")
	require.NoError(t, os.WriteFile(fakePMG, []byte(`#!/bin/sh
printf '%s %s\n' "${PMG_CLOUD_ENABLED:-}" "$*" >> "$PMG_TEST_CALLS"
case "$*" in
  *--help*) printf '%s\n' '--require-policy   Fetch only the cloud policy' ;;
esac
`), 0o755))

	cmd := exec.Command("sh", "action/policy.sh", fakePMG)
	cmd.Env = append(os.Environ(), "PMG_CLOUD_ENABLED=true", "PMG_TEST_CALLS="+calls)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	data, err := os.ReadFile(calls)
	require.NoError(t, err)
	assert.Equal(t, []string{
		"false cloud sync --help",
		"true cloud sync --require-policy --timeout 20s",
	}, strings.Split(strings.TrimSpace(string(data)), "\n"))
}
