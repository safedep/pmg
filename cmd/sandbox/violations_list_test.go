package sandbox

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCacheFactory(t *testing.T) (cacheFactory, *pmgsandbox.ViolationCache) {
	t.Helper()
	dir := t.TempDir()
	cache := pmgsandbox.NewViolationCache(dir)
	return func() *pmgsandbox.ViolationCache { return cache }, cache
}

func sampleViolationsReport(target string) *pmgsandbox.ViolationReport {
	return &pmgsandbox.ViolationReport{
		SandboxName: pmgsandbox.DriverSeatbelt,
		PolicyName:  "npm-restrictive",
		Violations: []pmgsandbox.Violation{
			{Kind: pmgsandbox.ViolationKindFSWrite, Target: target, RuleLabel: "file-write"},
		},
	}
}

func runList(t *testing.T, factory cacheFactory, args ...string) (string, string, error) {
	t.Helper()
	cmd := newViolationsListCommand(factory)
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errOut.String(), err
}

func TestViolationsList_EmptyCache(t *testing.T) {
	factory, _ := newTestCacheFactory(t)

	stdout, stderr, err := runList(t, factory)
	require.NoError(t, err)
	assert.Empty(t, stdout)
	assert.Contains(t, stderr, "no violations cached")
}

func TestViolationsList_TwoEntriesNewestFirst(t *testing.T) {
	factory, cache := newTestCacheFactory(t)

	_, err := cache.Write(sampleViolationsReport("/Users/dev/older"))
	require.NoError(t, err)
	_, err = cache.Write(sampleViolationsReport("/Users/dev/newer"))
	require.NoError(t, err)

	stdout, _, err := runList(t, factory)
	require.NoError(t, err)

	assert.Contains(t, stdout, "RECORDED")
	assert.Contains(t, stdout, "SANDBOX")
	assert.Contains(t, stdout, "seatbelt")
	assert.Contains(t, stdout, "npm-restrictive")
	assert.Contains(t, stdout, "/Users/dev/older")
	assert.Contains(t, stdout, "/Users/dev/newer")

	newerIdx := strings.Index(stdout, "/Users/dev/newer")
	olderIdx := strings.Index(stdout, "/Users/dev/older")
	require.NotEqual(t, -1, newerIdx)
	require.NotEqual(t, -1, olderIdx)
	assert.Less(t, newerIdx, olderIdx, "newest entry should appear first")
}

func TestViolationsList_LimitOne(t *testing.T) {
	factory, cache := newTestCacheFactory(t)

	_, err := cache.Write(sampleViolationsReport("/Users/dev/a"))
	require.NoError(t, err)
	_, err = cache.Write(sampleViolationsReport("/Users/dev/b"))
	require.NoError(t, err)

	stdout, _, err := runList(t, factory, "--limit", "1")
	require.NoError(t, err)

	assert.Contains(t, stdout, "/Users/dev/b")
	assert.NotContains(t, stdout, "/Users/dev/a")
}

func TestViolationsListRejectsUnexpectedArgs(t *testing.T) {
	factory, _ := newTestCacheFactory(t)

	stdout, stderr, err := runList(t, factory, "extra")
	require.Error(t, err)
	assert.Contains(t, stderr, "unknown command")
	assert.Contains(t, stdout, "Usage:")
	assert.Contains(t, stdout, "list [flags]")
	assert.Contains(t, stdout, "pmg sandbox violations list --limit 20")
}

func TestViolationsListRejectsNegativeLimit(t *testing.T) {
	factory, _ := newTestCacheFactory(t)

	_, _, err := runList(t, factory, "--limit", "-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --limit")
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.InvalidArgument, usefulErr.Code())
}

func TestViolationsList_LimitZeroReturnsAll(t *testing.T) {
	factory, cache := newTestCacheFactory(t)

	for _, target := range []string{"/Users/dev/a", "/Users/dev/b", "/Users/dev/c"} {
		_, err := cache.Write(sampleViolationsReport(target))
		require.NoError(t, err)
	}

	stdout, _, err := runList(t, factory, "--limit", "0")
	require.NoError(t, err)

	assert.Contains(t, stdout, "/Users/dev/a")
	assert.Contains(t, stdout, "/Users/dev/b")
	assert.Contains(t, stdout, "/Users/dev/c")
}

func TestViolationsList_JSON(t *testing.T) {
	factory, cache := newTestCacheFactory(t)

	_, err := cache.Write(sampleViolationsReport("/Users/dev/x"))
	require.NoError(t, err)
	_, err = cache.Write(sampleViolationsReport("/Users/dev/y"))
	require.NoError(t, err)

	stdout, _, err := runList(t, factory, "--json")
	require.NoError(t, err)

	var payload struct {
		Entries []struct {
			Path        string `json:"path"`
			RecordedAt  string `json:"recorded_at"`
			SandboxName string `json:"sandbox_name"`
			PolicyName  string `json:"policy_name"`
			Primary     *struct {
				Kind      string `json:"kind"`
				Target    string `json:"target"`
				RuleLabel string `json:"rule_label"`
			} `json:"primary,omitempty"`
			ViolationCount int `json:"violation_count"`
		} `json:"entries"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &payload))
	require.Len(t, payload.Entries, 2)
	assert.Equal(t, "seatbelt", payload.Entries[0].SandboxName)
	assert.Equal(t, "npm-restrictive", payload.Entries[0].PolicyName)
	require.NotNil(t, payload.Entries[0].Primary)
	assert.Equal(t, "fs_write", payload.Entries[0].Primary.Kind)
	assert.Equal(t, 1, payload.Entries[0].ViolationCount)
}

func TestViolationsList_NoViolations_RendersDash(t *testing.T) {
	factory, cache := newTestCacheFactory(t)

	_, err := cache.Write(&pmgsandbox.ViolationReport{
		SandboxName: pmgsandbox.DriverSeatbelt,
		PolicyName:  "npm-restrictive",
		Violations:  nil,
	})
	require.NoError(t, err)

	stdout, _, err := runList(t, factory)
	require.NoError(t, err)
	assert.Contains(t, stdout, "seatbelt")
	assert.Contains(t, stdout, "—")
}

func TestViolationsList_NoViolations_JSONOmitsPrimary(t *testing.T) {
	factory, cache := newTestCacheFactory(t)

	_, err := cache.Write(&pmgsandbox.ViolationReport{
		SandboxName: pmgsandbox.DriverSeatbelt,
		PolicyName:  "npm-restrictive",
		Violations:  nil,
	})
	require.NoError(t, err)

	stdout, _, err := runList(t, factory, "--json")
	require.NoError(t, err)

	assert.NotContains(t, stdout, "\"primary\"")

	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &payload))
	entries, ok := payload["entries"].([]any)
	require.True(t, ok)
	require.Len(t, entries, 1)
}
