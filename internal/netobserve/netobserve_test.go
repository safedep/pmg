package netobserve

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/eventlog"
	"github.com/safedep/pmg/proxy/netpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var now = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func dest(host string, port uint16, count int, last time.Time) netpolicy.Destination {
	return netpolicy.Destination{Host: host, Port: port, Count: count, Allowed: true, FirstSeen: last.Add(-time.Hour), LastSeen: last}
}

func record(id, repo string, at time.Time, destinations ...netpolicy.Destination) Record {
	return Record{Observation: netpolicy.Observation{RunID: id, RepoRoot: repo, Destinations: destinations}, Timestamp: at}
}

func TestReadDecodesTheEventDetails(t *testing.T) {
	dir := t.TempDir()
	obs := netpolicy.Observation{RunID: "run1", RepoRoot: "/repo", PackageManager: "npm",
		Destinations: []netpolicy.Destination{dest("2606:4700::1", 443, 2, now)}}
	details := map[string]any{"run_id": obs.RunID, "repo_root": obs.RepoRoot, "package_manager": obs.PackageManager, "destinations": obs.Destinations}
	good, err := json.Marshal(eventlog.Event{Timestamp: now, EventType: string(audit.EventTypeNetworkObservation), Details: details})
	require.NoError(t, err)
	bad, err := json.Marshal(eventlog.Event{Timestamp: now, EventType: string(audit.EventTypeNetworkObservation), Details: map[string]any{"run_id": ""}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "20261016-pmg.log"), append(append(good, '\n'), append(bad, '\n')...), 0o644))

	records, err := Read(dir, time.Time{})
	require.NoError(t, err)
	require.Len(t, records, 1, "the observation without a run id is skipped")
	assert.Equal(t, "run1", records[0].RunID)
	assert.Equal(t, now, records[0].Timestamp)
	require.Len(t, records[0].Destinations, 1)
	assert.Equal(t, uint16(443), records[0].Destinations[0].Port)
	assert.Equal(t, "[2606:4700::1]:443", records[0].Destinations[0].Address())
	assert.True(t, records[0].Destinations[0].LastSeen.Equal(now))
}

func TestSelect(t *testing.T) {
	records := []Record{
		record("b", "/repo", now.Add(-time.Hour)),
		record("a", "/repo", now.Add(-2*time.Hour)),
		record("c", "/other", now),
	}
	byRun := Select(records, Selector{RunID: "c", RepoRoot: "/repo"})
	require.Len(t, byRun, 1)
	assert.Equal(t, "c", byRun[0].RunID, "--run ignores the repository")

	ofRepo := Select(records, Selector{RepoRoot: "/repo"})
	require.Len(t, ofRepo, 2)
	assert.Equal(t, []string{"a", "b"}, []string{ofRepo[0].RunID, ofRepo[1].RunID}, "oldest first")

	last := Select(records, Selector{RepoRoot: "/repo", Last: true})
	require.Len(t, last, 1)
	assert.Equal(t, "b", last[0].RunID)

	assert.Empty(t, Select(records, Selector{RunID: "nope"}))
}

func TestMergeAddsCountsAndKeepsTheNewestDecision(t *testing.T) {
	older := dest("registry.npmjs.org", 443, 2, now.Add(-2*time.Hour))
	older.PID = 7
	newer := netpolicy.Destination{Host: "registry.npmjs.org", Port: 443, Count: 3, Allowed: false, Rule: "*:*",
		FirstSeen: now.Add(-time.Hour), LastSeen: now, PID: 9}
	rows := Merge([]Record{
		record("a", "/repo", now.Add(-2*time.Hour), older, dest("github.com", 443, 1, now.Add(-2*time.Hour))),
		record("b", "/repo", now, newer),
	})
	require.Len(t, rows, 2)
	assert.Equal(t, "github.com:443", rows[0].Address())
	registry := rows[1]
	assert.Equal(t, 5, registry.Count)
	assert.False(t, registry.Allowed)
	assert.Equal(t, "*:*", registry.Rule)
	assert.Equal(t, 0, registry.PID, "a pid belongs to one run")
	assert.True(t, registry.FirstSeen.Equal(older.FirstSeen))
	assert.True(t, registry.LastSeen.Equal(now))

	single := Merge([]Record{record("a", "/repo", now, older)})
	assert.Zero(t, single[0].PID, "a pid never survives the fold")
}

func TestParseWindow(t *testing.T) {
	since, err := ParseWindow("30d", now)
	require.NoError(t, err)
	assert.Equal(t, now.AddDate(0, 0, -30), since)
	since, err = ParseWindow("12h", now)
	require.NoError(t, err)
	assert.Equal(t, now.Add(-12*time.Hour), since)
	for _, bad := range []string{"0d", "-1d", "soon", ""} {
		_, err := ParseWindow(bad, now)
		assert.Error(t, err, bad)
	}
}
