package eventlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeLogLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	data := ""
	for _, line := range lines {
		data += line + "\n"
	}
	require.NoError(t, os.WriteFile(path, []byte(data), 0o644))
}

func TestReadFiltersByTypeAndTimeAcrossRotatedFiles(t *testing.T) {
	dir := t.TempDir()
	day1 := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	day2 := day1.Add(24 * time.Hour)
	line := func(at time.Time, kind, msg string) string {
		data, err := json.Marshal(Event{Timestamp: at, EventType: kind, Message: msg})
		require.NoError(t, err)
		return string(data)
	}
	writeLogLines(t, filepath.Join(dir, "20261015-pmg.log"),
		line(day1, "network_observation", "old"),
		line(day1.Add(time.Hour), "session_complete", "other"),
		"not json at all",
	)
	writeLogLines(t, filepath.Join(dir, "20261016-pmg.log"),
		line(day2, "network_observation", "new"),
	)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignored"), 0o644))

	events, err := Read(dir, time.Time{}, "network_observation")
	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, "old", events[0].Message)
	assert.Equal(t, "new", events[1].Message)

	events, err = Read(dir, day1.Add(2*time.Hour), "network_observation")
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "new", events[0].Message)

	events, err = Read(dir, time.Time{})
	require.NoError(t, err)
	assert.Len(t, events, 3, "no type filter reads every parsable event")
}

func TestReadOfAMissingDirectoryIsEmpty(t *testing.T) {
	events, err := Read(filepath.Join(t.TempDir(), "missing"), time.Time{}, "network_observation")
	require.NoError(t, err)
	assert.Empty(t, events)
}
