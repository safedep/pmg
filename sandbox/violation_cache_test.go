package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleCacheReport(label string) *ViolationReport {
	return &ViolationReport{
		SandboxName:   "seatbelt",
		PolicyName:    "npm-restrictive",
		CorrelationID: "corr-1",
		Violations: []Violation{
			{Kind: ViolationKindFSRead, Target: "/tmp/x", RuleLabel: label},
		},
	}
}

func newFixedClock(start time.Time) func() time.Time {
	t := start
	return func() time.Time {
		t = t.Add(time.Millisecond)
		return t
	}
}

func TestViolationCacheWriteAndList(t *testing.T) {
	dir := t.TempDir()
	c := NewViolationCache(dir, WithClock(newFixedClock(time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC))))

	path, err := c.Write(sampleCacheReport("rule-a"))
	require.NoError(t, err)
	assert.FileExists(t, path)

	entries, err := c.List()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, ViolationCacheSchemaVersion, entries[0].Record.SchemaVersion)
	assert.Equal(t, "rule-a", entries[0].Record.Report.Violations[0].RuleLabel)

	latest, err := c.Latest()
	require.NoError(t, err)
	require.NotNil(t, latest)
	assert.Equal(t, path, latest.Path)
}

func TestViolationCacheRotation(t *testing.T) {
	dir := t.TempDir()
	c := NewViolationCache(dir,
		WithRetention(10),
		WithClock(newFixedClock(time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC))),
	)

	for i := 0; i < 13; i++ {
		_, err := c.Write(sampleCacheReport("rule"))
		require.NoError(t, err)
	}

	entries, err := c.List()
	require.NoError(t, err)
	assert.Len(t, entries, 10)

	dirents, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, dirents, 10)

	latest, err := c.Latest()
	require.NoError(t, err)
	require.NotNil(t, latest)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, filepath.Base(e.Path))
	}
	assert.Equal(t, filepath.Base(latest.Path), names[0])
}

func TestViolationCacheSerializedSchemaVersionPresent(t *testing.T) {
	dir := t.TempDir()
	c := NewViolationCache(dir)

	path, err := c.Write(sampleCacheReport("rule"))
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))
	assert.EqualValues(t, ViolationCacheSchemaVersion, raw["schema_version"])
}

func TestViolationCacheCorruptFileSkipped(t *testing.T) {
	dir := t.TempDir()
	c := NewViolationCache(dir)

	_, err := c.Write(sampleCacheReport("good"))
	require.NoError(t, err)

	bad := filepath.Join(dir, "violation-bad.json")
	require.NoError(t, os.WriteFile(bad, []byte("{not json"), 0o644))

	entries, err := c.List()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "good", entries[0].Record.Report.Violations[0].RuleLabel)
}

func TestViolationCacheWrongSchemaVersionSkipped(t *testing.T) {
	dir := t.TempDir()
	c := NewViolationCache(dir)

	valid := ViolationCacheRecord{
		SchemaVersion: ViolationCacheSchemaVersion,
		RecordedAt:    time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC),
		Report:        sampleCacheReport("valid"),
	}
	writeViolationCacheRecord(t, dir, "violation-20260514T100000.000000000Z-valid.json", valid)

	missingVersion := valid
	missingVersion.SchemaVersion = 0
	missingVersion.Report = sampleCacheReport("missing-version")
	writeViolationCacheRecord(t, dir, "violation-20260514T100001.000000000Z-missing.json", missingVersion)

	futureVersion := valid
	futureVersion.SchemaVersion = ViolationCacheSchemaVersion + 1
	futureVersion.Report = sampleCacheReport("future-version")
	writeViolationCacheRecord(t, dir, "violation-20260514T100002.000000000Z-future.json", futureVersion)

	entries, err := c.List()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "valid", entries[0].Record.Report.Violations[0].RuleLabel)

	latest, err := c.Latest()
	require.NoError(t, err)
	require.NotNil(t, latest)
	assert.Equal(t, "valid", latest.Record.Report.Violations[0].RuleLabel)
}

func TestViolationCacheWriteNilReport(t *testing.T) {
	c := NewViolationCache(t.TempDir())
	_, err := c.Write(nil)
	assert.Error(t, err)
}

func TestViolationCacheListEmptyMissingDir(t *testing.T) {
	c := NewViolationCache(filepath.Join(t.TempDir(), "missing"))
	entries, err := c.List()
	require.NoError(t, err)
	assert.Empty(t, entries)

	latest, err := c.Latest()
	require.NoError(t, err)
	assert.Nil(t, latest)
}

func writeViolationCacheRecord(t *testing.T, dir, name string, rec ViolationCacheRecord) {
	t.Helper()

	data, err := json.Marshal(rec)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o644))
}
