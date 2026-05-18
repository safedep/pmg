package sandbox

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/usefulerror"
)

func sampleReport() *pmgsandbox.ViolationReport {
	return &pmgsandbox.ViolationReport{
		SandboxName:   pmgsandbox.DriverSeatbelt,
		PolicyName:    "npm-restrictive",
		CorrelationID: "corr-abc",
		Violations: []pmgsandbox.Violation{
			{
				Kind:      pmgsandbox.ViolationKindFSWrite,
				Target:    "/Users/dev/project/.env",
				RuleLabel: "file-write* on sensitive project file",
				Process:   "npm",
				RawLog:    "deny file-write* /Users/dev/project/.env",
			},
		},
	}
}

func writeFixtureCache(t *testing.T, dir string) *pmgsandbox.ViolationCache {
	t.Helper()
	cache := pmgsandbox.NewViolationCache(dir, pmgsandbox.WithClock(func() time.Time {
		return time.Date(2026, 5, 14, 10, 30, 0, 0, time.UTC)
	}))
	_, err := cache.Write(sampleReport())
	require.NoError(t, err)
	return cache
}

func runExplainCmd(t *testing.T, factory cacheFactory, args []string, stdin string) (string, string, error) {
	t.Helper()
	cmd := newExplainCommand(factory)
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errOut.String(), err
}

func TestExplainLastEmptyCache(t *testing.T) {
	dir := t.TempDir()
	factory := func() *pmgsandbox.ViolationCache { return pmgsandbox.NewViolationCache(dir) }

	stdout, _, err := runExplainCmd(t, factory, []string{"--last"}, "")
	require.Error(t, err)

	fe, ok := err.(*explainFailError)
	require.True(t, ok)
	assert.Equal(t, ExitCodeExplainFail, fe.ExitCode())
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, usefulerror.ErrCodeNotFound, usefulErr.Code())
	assert.Empty(t, stdout)
	assert.Contains(t, err.Error(), "no violations cached")
}

func TestExplainLastRendersHuman(t *testing.T) {
	dir := t.TempDir()
	writeFixtureCache(t, dir)
	factory := func() *pmgsandbox.ViolationCache { return pmgsandbox.NewViolationCache(dir) }

	stdout, _, err := runExplainCmd(t, factory, []string{"--last"}, "")
	require.NoError(t, err)

	assert.Contains(t, stdout, "seatbelt")
	assert.Contains(t, stdout, "npm-restrictive")
	assert.Contains(t, stdout, "Reason:")
	assert.Contains(t, stdout, "Details:")
	assert.Contains(t, stdout, "Primary violation:")
	assert.Contains(t, stdout, "/Users/dev/project/.env")
}

func TestExplainLastJSON(t *testing.T) {
	dir := t.TempDir()
	writeFixtureCache(t, dir)
	factory := func() *pmgsandbox.ViolationCache { return pmgsandbox.NewViolationCache(dir) }

	stdout, _, err := runExplainCmd(t, factory, []string{"--last", "--json"}, "")
	require.NoError(t, err)

	var payload struct {
		Explanation struct {
			Hint              string `json:"hint"`
			Details           string `json:"details"`
			SuggestedOverride string `json:"suggested_override"`
			Primary           struct {
				Kind   string `json:"kind"`
				Target string `json:"target"`
			} `json:"primary"`
		} `json:"explanation"`
		Report     *pmgsandbox.ViolationReport `json:"report"`
		RecordedAt string                      `json:"recorded_at"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &payload))

	assert.NotEmpty(t, payload.Explanation.Hint)
	assert.Equal(t, "fs_write", payload.Explanation.Primary.Kind)
	assert.Equal(t, "/Users/dev/project/.env", payload.Explanation.Primary.Target)
	require.NotNil(t, payload.Report)
	assert.Equal(t, pmgsandbox.DriverSeatbelt, payload.Report.SandboxName)
	assert.NotEmpty(t, payload.RecordedAt)
}

func TestExplainLastRejectsCacheRecordWithNilReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "violation-99999999T999999.999999999Z-bad.json")
	body := []byte(`{"schema_version":1,"recorded_at":"2026-05-14T10:30:00Z","report":null}`)
	require.NoError(t, os.WriteFile(path, body, 0o644))
	factory := func() *pmgsandbox.ViolationCache { return pmgsandbox.NewViolationCache(dir) }

	stdout, _, err := runExplainCmd(t, factory, []string{"--last"}, "")
	require.Error(t, err)

	fe, ok := err.(*explainFailError)
	require.True(t, ok)
	assert.Equal(t, ExitCodeExplainFail, fe.ExitCode())
	assert.Empty(t, stdout)
	assert.Contains(t, err.Error(), "cache JSON is missing report")
}

func TestExplainStdinValid(t *testing.T) {
	rec := pmgsandbox.ViolationCacheRecord{
		SchemaVersion: pmgsandbox.ViolationCacheSchemaVersion,
		RecordedAt:    time.Date(2026, 5, 14, 10, 30, 0, 0, time.UTC),
		Report:        sampleReport(),
	}
	data, err := json.Marshal(rec)
	require.NoError(t, err)

	factory := func() *pmgsandbox.ViolationCache {
		t.Fatal("cache should not be consulted in stdin mode")
		return nil
	}

	stdout, _, err := runExplainCmd(t, factory, []string{"-"}, string(data))
	require.NoError(t, err)
	assert.Contains(t, stdout, "Primary violation:")
	assert.Contains(t, stdout, "/Users/dev/project/.env")
}

func TestExplainStdinInvalidJSON(t *testing.T) {
	factory := func() *pmgsandbox.ViolationCache { return nil }
	_, _, err := runExplainCmd(t, factory, []string{"-"}, "not json {{")
	require.Error(t, err)
	fe, ok := err.(*explainFailError)
	require.True(t, ok)
	assert.Equal(t, ExitCodeExplainFail, fe.ExitCode())
	assert.Contains(t, err.Error(), "parse stdin JSON")
}

func TestExplainStdinSchemaVersion(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "missing schema_version",
			body: `{"report":{"SandboxName":"seatbelt","PolicyName":"p","Violations":[{"Kind":"fs_write","Target":"/x","RuleLabel":"r"}]}}`,
			want: "missing schema_version",
		},
		{
			name: "unknown schema_version",
			body: `{"schema_version":999,"report":{"SandboxName":"seatbelt","PolicyName":"p"}}`,
			want: "unknown schema_version",
		},
	}

	factory := func() *pmgsandbox.ViolationCache { return nil }

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := runExplainCmd(t, factory, []string{"-"}, tc.body)
			require.Error(t, err)
			fe, ok := err.(*explainFailError)
			require.True(t, ok)
			assert.Equal(t, ExitCodeExplainFail, fe.ExitCode())
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestExplainMutualExclusion(t *testing.T) {
	factory := func() *pmgsandbox.ViolationCache { return nil }
	_, _, err := runExplainCmd(t, factory, []string{"--last", "-"}, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestExplainRejectsUnexpectedArgsWithUsage(t *testing.T) {
	factory := func() *pmgsandbox.ViolationCache { return nil }
	stdout, stderr, err := runExplainCmd(t, factory, []string{"one", "two"}, "")
	require.Error(t, err)
	assert.Contains(t, stderr, "accepts at most 1 arg(s), received 2")
	assert.Contains(t, stdout, "Usage:")
	assert.Contains(t, stdout, "explain [--last | -] [flags]")
	assert.Contains(t, stdout, "pmg sandbox explain --last")
}

func TestExplainNoMode(t *testing.T) {
	factory := func() *pmgsandbox.ViolationCache { return nil }
	_, _, err := runExplainCmd(t, factory, []string{}, "")
	require.Error(t, err)
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, usefulerror.ErrCodeInvalidArgument, usefulErr.Code())
	assert.Contains(t, err.Error(), "no input")
	assert.Contains(t, err.Error(), "--last")
}
