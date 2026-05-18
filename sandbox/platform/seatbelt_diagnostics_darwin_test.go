//go:build darwin
// +build darwin

package platform

import (
	"testing"

	"github.com/safedep/pmg/sandbox"
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

func TestParseSeatbeltLogPayloadEmptyTarget(t *testing.T) {
	msg := `Sandbox: node(123) deny(1) default ` + seatbeltLogMessage("run-1", "default", "")

	payload, ok := parseSeatbeltLogPayload(msg)
	require.True(t, ok)
	assert.Equal(t, "run-1", payload.RunID)
	assert.Equal(t, "default", payload.Kind)
	assert.Empty(t, payload.Target)
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
	assert.Equal(t, sandbox.ViolationKindFSRead, violations[0].Kind)
	assert.Equal(t, "file-read", violations[0].RawKind)
	assert.Equal(t, "/tmp/.env", violations[0].Target)
	assert.Equal(t, "/tmp/.env", violations[0].RuleTarget)
	assert.Equal(t, "node", violations[0].Process)
}

// Regression: a denial that hits the catch-all `(deny default ...)` rule
// must still be classified as the typed kind (and get a typed label) by
// recovering the verb from the sandbox-exec preamble. Without this, the
// actual failure-causing operation (e.g. a write) gets buried below
// incidental typed reads in primaryViolation ranking.
func TestExtractSeatbeltViolationsRecoversTypedKindFromDefaultDeny(t *testing.T) {
	entries := []seatbeltLogEntry{
		{
			EventMessage: `Sandbox: node(59437) deny(1) file-write-data /Users/dev/project/.astro/types.d.ts ` +
				seatbeltLogMessage("run-1", "default", ""),
			Process: "node",
		},
		{
			EventMessage: `Sandbox: node(59438) deny(1) network-outbound 1.2.3.4:443 ` +
				seatbeltLogMessage("run-1", "default", ""),
			Process: "node",
		},
	}

	violations := extractSeatbeltViolations(entries, "run-1")
	require.Len(t, violations, 2)

	// File write hit the catch-all deny — Kind is recovered, RawKind stays
	// "default" to preserve the "catch-all match" signal, and the label
	// reflects the recovered kind so users see "write access denied".
	assert.Equal(t, sandbox.ViolationKindFSWrite, violations[0].Kind)
	assert.Equal(t, "default", violations[0].RawKind)
	assert.Equal(t, "/Users/dev/project/.astro/types.d.ts", violations[0].Target)
	assert.Equal(t, "write access denied: /Users/dev/project/.astro/types.d.ts", violations[0].RuleLabel)

	// Unrecognized verb (network-outbound) stays generic — no over-claiming.
	assert.Equal(t, sandbox.ViolationKindGenericDeny, violations[1].Kind)
	assert.Equal(t, "default", violations[1].RawKind)
}

func TestInferSeatbeltKindFromRawLog(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantKind  sandbox.ViolationKind
		wantLabel string
		wantOK    bool
	}{
		{
			name:      "file-write-data maps to fs_write",
			raw:       `Sandbox: node(1) deny(1) file-write-data /tmp/x`,
			wantKind:  sandbox.ViolationKindFSWrite,
			wantLabel: "file-write",
			wantOK:    true,
		},
		{
			name:      "file-write-unlink maps to fs_delete_or_rename",
			raw:       `Sandbox: node(1) deny(1) file-write-unlink /tmp/x`,
			wantKind:  sandbox.ViolationKindFSDeleteOrRename,
			wantLabel: "file-write-unlink",
			wantOK:    true,
		},
		{
			name:      "file-rename maps to fs_delete_or_rename",
			raw:       `Sandbox: node(1) deny(1) file-rename /tmp/a`,
			wantKind:  sandbox.ViolationKindFSDeleteOrRename,
			wantLabel: "file-write-unlink",
			wantOK:    true,
		},
		{
			name:      "file-read-metadata maps to fs_read",
			raw:       `Sandbox: node(1) deny(1) file-read-metadata /tmp/x`,
			wantKind:  sandbox.ViolationKindFSRead,
			wantLabel: "file-read",
			wantOK:    true,
		},
		{
			name:      "process-exec maps to exec",
			raw:       `Sandbox: node(1) deny(1) process-exec /usr/bin/curl`,
			wantKind:  sandbox.ViolationKindExec,
			wantLabel: "process-exec",
			wantOK:    true,
		},
		{
			name:     "process-fork is not exec",
			raw:      `Sandbox: node(1) deny(1) process-fork`,
			wantKind: sandbox.ViolationKindGenericDeny,
			wantOK:   false,
		},
		{
			name:     "network verb is not recognized",
			raw:      `Sandbox: node(1) deny(1) network-outbound 1.2.3.4:443`,
			wantKind: sandbox.ViolationKindGenericDeny,
			wantOK:   false,
		},
		{
			name:     "log without deny prefix is not recognized",
			raw:      `something unrelated`,
			wantKind: sandbox.ViolationKindGenericDeny,
			wantOK:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kind, label, ok := inferSeatbeltKindFromRawLog(tc.raw)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantKind, kind)
			if tc.wantOK {
				assert.Equal(t, tc.wantLabel, label)
			}
		})
	}
}
