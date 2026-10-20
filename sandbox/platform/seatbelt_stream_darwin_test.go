//go:build darwin

package platform

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeStreamTag = "run-1"

const fakeStreamEntry = `{"eventMessage":"Sandbox: cat(1) deny(1) file-read-data /x\nPMG_SBX|run=run-1|kind=file-read|target=%2Fx","processImagePath":"/kernel"}`

// fakeSentinelLine is the stream line of a sentinel denial of fakeStreamTag.
func fakeSentinelLine(t *testing.T, target string) string {
	t.Helper()
	line, err := json.Marshal(seatbeltLogEntry{
		EventMessage:     "Sandbox: cat(2) deny(1) file-read-data /private/etc/hosts\n" + seatbeltLogMessage(fakeStreamTag, seatbeltKindSentinel, target),
		ProcessImagePath: "/kernel",
	})
	require.NoError(t, err)
	return string(line)
}

// fakeLogStream runs script under the real stream wrapper. The script prints
// the lines a log stream would print, sentinels included.
func fakeLogStream(script string) *exec.Cmd {
	return seatbeltStreamCommand("/bin/sh", "-c", script)
}

func noopSentinel(string, string) error { return nil }

func printLines(lines ...string) string {
	script := ""
	for _, l := range lines {
		script += "printf '%s\\n' '" + l + "'; "
	}
	return script
}

func TestSeatbeltLogStreamCollectsEntriesUntilEndSentinel(t *testing.T) {
	cmd := fakeLogStream(`echo "Filtering the log data"; ` +
		printLines("not json", fakeSentinelLine(t, "start"), fakeStreamEntry, fakeSentinelLine(t, "end")) +
		`exec sleep 30`)

	st, err := startSeatbeltLogStream(cmd, fakeStreamTag, noopSentinel, time.Second)
	require.NoError(t, err)

	entries, complete := st.end()
	assert.True(t, complete)
	require.Len(t, entries, 1, "sentinels are not entries")
	assert.Equal(t, "/kernel", entries[0].ProcessImagePath)
	assert.NotNil(t, cmd.ProcessState, "end must reap the stream process")
}

// Without the end sentinel, PMG cannot know that the stream delivered every
// denial. The run then falls back to the log store.
func TestSeatbeltLogStreamWithoutEndSentinelIsIncomplete(t *testing.T) {
	tests := []struct {
		name   string
		script string
	}{
		{name: "stream ends early", script: printLines(fakeSentinelLine(t, "start"), fakeStreamEntry) + `sleep 0.1`},
		{name: "end sentinel never comes", script: printLines(fakeSentinelLine(t, "start"), fakeStreamEntry) + `exec sleep 30`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st, err := startSeatbeltLogStream(fakeLogStream(tc.script), fakeStreamTag, noopSentinel, time.Second)
			require.NoError(t, err)
			st.endTimeout = 300 * time.Millisecond

			entries, complete := st.end()
			assert.False(t, complete)
			assert.Len(t, entries, 1)
		})
	}
}

// When pmg dies, the kernel closes its end of the input pipe. The stream must
// then end, so a killed pmg leaves no log process behind.
func TestSeatbeltLogStreamEndsWhenInputCloses(t *testing.T) {
	st, err := startSeatbeltLogStream(fakeLogStream(printLines(fakeSentinelLine(t, "start"))+`exec sleep 30`),
		fakeStreamTag, noopSentinel, time.Second)
	require.NoError(t, err)

	require.NoError(t, st.stdin.Close())
	select {
	case <-st.done:
	case <-time.After(2 * time.Second):
		t.Fatal("the stream did not end after its input closed")
	}
	st.shutdown()
}

func TestSeatbeltLogStreamStartFailures(t *testing.T) {
	failingSentinel := func(string, string) error { return errors.New("sandbox-exec missing") }

	tests := []struct {
		name    string
		script  string
		trigger seatbeltSentinelTrigger
	}{
		{name: "ends before the start sentinel", script: `exit 0`, trigger: noopSentinel},
		{name: "start sentinel never comes", script: `echo "Filtering the log data"; exec sleep 30`, trigger: noopSentinel},
		{name: "sentinel cannot be made", script: `exec sleep 30`, trigger: failingSentinel},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := fakeLogStream(tc.script)

			st, err := startSeatbeltLogStream(cmd, fakeStreamTag, tc.trigger, 300*time.Millisecond)
			require.Error(t, err)
			assert.Nil(t, st)
			assert.NotNil(t, cmd.ProcessState, "a failed start must not leave the process running")
		})
	}
}

// A sentinel denial is PMG's own probe, so it never becomes a violation, also
// when the run falls back to the log store.
func TestExtractSeatbeltViolationsSkipsSentinels(t *testing.T) {
	var sentinel seatbeltLogEntry
	require.NoError(t, json.Unmarshal([]byte(fakeSentinelLine(t, "end")), &sentinel))
	var denial seatbeltLogEntry
	require.NoError(t, json.Unmarshal([]byte(fakeStreamEntry), &denial))

	violations := extractSeatbeltViolations([]seatbeltLogEntry{sentinel, denial}, fakeStreamTag)
	require.Len(t, violations, 1)
	assert.Equal(t, "/x", violations[0].Target)
}

// The real sentinel must reach a real log stream.
func TestTriggerSeatbeltSentinelReachesLogStream(t *testing.T) {
	requireSandboxExec(t)

	tag := generateLogTag()
	st, err := startSeatbeltLogStream(seatbeltLogStreamCommand(tag), tag, triggerSeatbeltSentinel, seatbeltStreamReadyTimeout)
	require.NoError(t, err)

	_, complete := st.end()
	assert.True(t, complete)
}

// Close must stop the stream, so an interrupted run leaves no log process.
func TestSeatbeltCloseStopsLogStream(t *testing.T) {
	requireSandboxExec(t)

	sb, err := newSeatbeltSandbox()
	require.NoError(t, err)

	cmd := exec.Command("/usr/bin/true")
	result, err := sb.Execute(context.Background(), cmd, seatbeltCleanExitPolicy("/nonexistent/.env"), nil)
	require.NoError(t, err)
	require.NotNil(t, sb.stream, "Execute must start the log stream")
	stream := sb.stream

	require.NoError(t, result.Close())
	assert.Nil(t, sb.stream)
	assert.NotNil(t, stream.cmd.ProcessState, "Close must reap the stream process")
}
