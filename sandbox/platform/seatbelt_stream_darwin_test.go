//go:build darwin

package platform

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeStreamEntry = `{"eventMessage":"Sandbox: cat(1) deny(1) file-read-data /x\nPMG_SBX|run=run-1|kind=file-read|target=%2Fx","processImagePath":"/kernel"}`

// fakeLogStream runs script under the real stream wrapper.
func fakeLogStream(script string) *exec.Cmd {
	return seatbeltStreamCommand("/bin/sh", "-c", script)
}

func TestSeatbeltLogStreamCollectsEntriesAfterHeader(t *testing.T) {
	cmd := fakeLogStream(`echo "Filtering the log data"; echo 'not json'; printf '%s\n' '` + fakeStreamEntry + `'; exec sleep 30`)

	st, err := startSeatbeltLogStream(cmd, time.Second)
	require.NoError(t, err)

	entries, complete := st.stop(200 * time.Millisecond)
	assert.True(t, complete)
	require.Len(t, entries, 1)
	assert.Equal(t, "/kernel", entries[0].ProcessImagePath)
	assert.NotNil(t, cmd.ProcessState, "stop must reap the stream process")
}

// When pmg dies, the kernel closes its end of the input pipe. The stream must
// then end, so a killed pmg leaves no log process behind.
func TestSeatbeltLogStreamEndsWhenInputCloses(t *testing.T) {
	cmd := fakeLogStream(`echo "Filtering the log data"; exec sleep 30`)

	st, err := startSeatbeltLogStream(cmd, time.Second)
	require.NoError(t, err)

	require.NoError(t, st.stdin.Close())
	select {
	case <-st.done:
	case <-time.After(2 * time.Second):
		t.Fatal("the stream did not end after its input closed")
	}

	_, complete := st.stop(0)
	assert.False(t, complete)
}

// A stream that ends on its own can miss entries. The run then falls back to
// the log store.
func TestSeatbeltLogStreamEndedEarlyIsIncomplete(t *testing.T) {
	cmd := fakeLogStream(`echo "Filtering the log data"; printf '%s\n' '` + fakeStreamEntry + `'; sleep 0.1`)

	st, err := startSeatbeltLogStream(cmd, time.Second)
	require.NoError(t, err)

	entries, complete := st.stop(2 * time.Second)
	assert.False(t, complete)
	assert.Len(t, entries, 1)
}

func TestSeatbeltLogStreamStartFailures(t *testing.T) {
	tests := []struct {
		name   string
		script string
	}{
		{name: "ends before it is ready", script: `exit 0`},
		{name: "never becomes ready", script: `exec sleep 30`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := fakeLogStream(tc.script)

			st, err := startSeatbeltLogStream(cmd, 200*time.Millisecond)
			require.Error(t, err)
			assert.Nil(t, st)
			assert.NotNil(t, cmd.ProcessState, "a failed start must not leave the process running")
		})
	}
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
