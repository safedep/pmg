//go:build darwin
// +build darwin

package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSeatbeltLogPayload(t *testing.T) {
	msg := `Sandbox: node(123) deny(1) file-write-data /Users/dev/project/.env ` +
		seatbeltLogMessage("run-1", "file-write", "/Users/dev/project/.env")

	payload, ok := parseSeatbeltLogPayload(msg)
	require.True(t, ok)
	assert.Equal(t, "run-1", payload.RunID)
	assert.Equal(t, "file-write", payload.Kind)
	assert.Equal(t, "/Users/dev/project/.env", payload.Target)
}

func TestExtractSeatbeltDeniedPath(t *testing.T) {
	payload := &seatbeltLogPayload{
		RunID:  "run-1",
		Kind:   "file-read",
		Target: "**/.env",
	}

	raw := `Sandbox: node(123) deny(1) file-read-data ./.env ` + seatbeltLogMessage("run-1", "file-read", "**/.env")
	assert.Equal(t, "./.env", extractSeatbeltDeniedPath(raw, payload))
}

func TestDecodeSeatbeltLogEntries(t *testing.T) {
	data := []byte(`[
		{"eventMessage":"entry-1","process":"node"},
		{"eventMessage":"entry-2","process":"npm"}
	]`)

	entries, err := decodeSeatbeltLogEntries(data)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.Equal(t, "entry-1", entries[0].EventMessage)
	assert.Equal(t, "npm", entries[1].Process)
}

func TestExtractSeatbeltViolations(t *testing.T) {
	entries := []seatbeltLogEntry{
		{
			EventMessage: "Sandbox deny " + seatbeltLogMessage("run-1", "file-read", "/tmp/.env"),
			Process:      "node",
		},
		{
			EventMessage: "Sandbox deny " + seatbeltLogMessage("run-2", "file-write", "/tmp/out"),
			Process:      "npm",
		},
	}

	violations := extractSeatbeltViolations(entries, "run-1")
	require.Len(t, violations, 1)
	assert.Equal(t, "file-read", violations[0].Kind)
	assert.Equal(t, "/tmp/.env", violations[0].Target)
	assert.Equal(t, "/tmp/.env", violations[0].RuleTarget)
	assert.Equal(t, "node", violations[0].Process)
}
