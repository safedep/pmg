//go:build darwin

package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeStreamTag = "run-1"
const fakeStreamNonce = "n1"

const fakeStreamEntry = `{"eventMessage":"Sandbox: cat(1) deny(1) file-read-data /x\nPMG_SBX|run=run-1|kind=file-read|target=%2Fx","processImagePath":"/kernel"}`

// fakeSentinelLine is the stream line of the sentinel denial of phase, as the
// kernel writes it for fakeStreamTag and fakeStreamNonce.
func fakeSentinelLine(t *testing.T, phase string) string {
	t.Helper()
	return fakeSentinelLineFrom(t, seatbeltKernelImagePath, phase)
}

// fakeSentinelLineFrom is a sentinel line that the process at imagePath wrote.
func fakeSentinelLineFrom(t *testing.T, imagePath, phase string) string {
	t.Helper()
	line, err := json.Marshal(seatbeltLogEntry{
		EventMessage:     "Sandbox: cat(2) deny(1) file-read-data /private/etc/hosts\n" + seatbeltLogMessage(fakeStreamTag, seatbeltKindSentinel, phase+"-"+fakeStreamNonce),
		ProcessImagePath: imagePath,
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

	st, err := startSeatbeltLogStream(cmd, fakeStreamTag, fakeStreamNonce, noopSentinel, time.Second)
	require.NoError(t, err)

	entries, complete := st.end(false)
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
			st, err := startSeatbeltLogStream(fakeLogStream(tc.script), fakeStreamTag, fakeStreamNonce, noopSentinel, time.Second)
			require.NoError(t, err)
			st.endTimeout = 300 * time.Millisecond

			entries, complete := st.end(false)
			assert.False(t, complete)
			assert.Len(t, entries, 1)
		})
	}
}

// When pmg dies, the kernel closes its end of the input pipe. The stream must
// then end, so a killed pmg leaves no log process behind.
func TestSeatbeltLogStreamEndsWhenInputCloses(t *testing.T) {
	st, err := startSeatbeltLogStream(fakeLogStream(printLines(fakeSentinelLine(t, "start"))+`exec sleep 30`),
		fakeStreamTag, fakeStreamNonce, noopSentinel, time.Second)
	require.NoError(t, err)

	require.NoError(t, st.stdin.Close())
	select {
	case <-st.done:
	case <-time.After(2 * time.Second):
		t.Fatal("the stream did not end after its input closed")
	}
	st.shutdown()
}

// A stream that ignores the stop is killed with its whole process group, so
// no log process survives the run.
func TestSeatbeltLogStreamShutdownKillsStuckStream(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "stream.pid")
	cmd := fakeLogStream(printLines(fakeSentinelLine(t, "start")) +
		`echo $$ > '` + pidFile + `'; trap '' TERM; exec sleep 30`)

	st, err := startSeatbeltLogStream(cmd, fakeStreamTag, fakeStreamNonce, noopSentinel, time.Second)
	require.NoError(t, err)

	var pid int
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(data)))
		return err == nil
	}, time.Second, 10*time.Millisecond)

	st.shutdown()

	assert.NotNil(t, cmd.ProcessState, "shutdown must reap the wrapper")
	assert.Eventually(t, func() bool {
		return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
	}, 2*time.Second, 50*time.Millisecond, "the stuck stream process must not survive")
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

			st, err := startSeatbeltLogStream(cmd, fakeStreamTag, fakeStreamNonce, tc.trigger, 300*time.Millisecond)
			require.Error(t, err)
			assert.Nil(t, st)
			assert.NotNil(t, cmd.ProcessState, "a failed start must not leave the process running")
		})
	}
}

// fakeDenialLine is the stream line of a denial of fakeStreamTag by process
// pid. A catch-all denial carries no rule target.
func fakeDenialLine(t *testing.T, pid int, kind, operation, operand string) string {
	t.Helper()
	target := operand
	if kind == seatbeltKindDefault {
		target = ""
	}
	line, err := json.Marshal(seatbeltLogEntry{
		EventMessage:     fmt.Sprintf("Sandbox: node(%d) deny(1) %s %s\n%s", pid, operation, operand, seatbeltLogMessage(fakeStreamTag, kind, target)),
		ProcessImagePath: "/kernel",
	})
	require.NoError(t, err)
	return string(line)
}

// startFakeStream starts a fake stream that prints lines. The stream then
// waits when wait is true, and ends early when it is false.
func startFakeStream(t *testing.T, lines []string, wait bool) *seatbeltLogStream {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stream.ndjson")
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600))

	tail := "exec sleep 30"
	if !wait {
		tail = "sleep 0.1"
	}
	st, err := startSeatbeltLogStream(fakeLogStream(`cat '`+path+`'; `+tail), fakeStreamTag, fakeStreamNonce, noopSentinel, time.Second)
	require.NoError(t, err)
	t.Cleanup(st.shutdown)
	return st
}

func fakeSeatbeltSandbox(st *seatbeltLogStream) *seatbeltSandbox {
	return &seatbeltSandbox{logTag: fakeStreamTag, policyName: "exec", startedAt: time.Now(), stream: st}
}

func violationTargets(report *sandbox.ViolationReport) []string {
	targets := make([]string, 0, len(report.Violations))
	for _, v := range report.Violations {
		targets = append(targets, v.Target)
	}
	return targets
}

// Noise has a buffer of its own, so it cannot push out a signal denial, which
// a clean run must record. A catch-all denial with a path is signal too. A
// clean run drops the noise, so a full noise buffer does not send it to the
// slow log store.
func TestSeatbeltCleanRunKeepsSignalAfterNoise(t *testing.T) {
	lines := []string{fakeSentinelLine(t, "start")}
	for i := 0; i < seatbeltStreamEntryCap+100; i++ {
		lines = append(lines, fakeDenialLine(t, 7, seatbeltKindDefault, "sysctl-read", fmt.Sprintf("kern.noise%d", i)))
	}
	lines = append(lines,
		fakeDenialLine(t, 8, "file-read", "file-read-data", "/Users/dev/.ssh/id_rsa"),
		fakeDenialLine(t, 8, seatbeltKindDefault, "file-write-data", "/Users/dev/.zshrc"),
		fakeSentinelLine(t, "end"))

	start := time.Now()
	report, err := fakeSeatbeltSandbox(startFakeStream(t, lines, true)).BestEffortViolation(nil)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, report, "the signal must not be lost behind the noise")
	assert.Equal(t, []string{"/Users/dev/.ssh/id_rsa", "/Users/dev/.zshrc"}, violationTargets(report))
	// The fallback polls the log store for seatbeltCleanFallbackWait. A full
	// buffer takes a slow runner about 0.5s to read.
	assert.Less(t, elapsed, seatbeltCleanFallbackWait*3/4, "a clean run must not query the log store for dropped noise")
}

// A complete stream with no denial is the whole answer, so a failed run does
// not query the log store either.
func TestSeatbeltFailedRunWithoutDenialSkipsLogStore(t *testing.T) {
	st := startFakeStream(t, []string{fakeSentinelLine(t, "start"), fakeSentinelLine(t, "end")}, true)

	start := time.Now()
	report, err := fakeSeatbeltSandbox(st).BestEffortViolation(errors.New("exit status 1"))
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Nil(t, report)
	assert.Less(t, elapsed, 500*time.Millisecond)
}

// The stream keeps every denial as the kernel logged it. The same file read
// by two programs, and two files whose paths share their last part, stay
// separate entries.
func TestSeatbeltLogStreamKeepsEveryDenial(t *testing.T) {
	lines := []string{
		fakeSentinelLine(t, "start"),
		strings.Replace(fakeDenialLine(t, 7, "file-read", "file-read-data", "/Users/dev/.netrc"), "node(7)", "git(7)", 1),
		fakeDenialLine(t, 8, "file-read", "file-read-data", "/Users/dev/.netrc"),
		fakeDenialLine(t, 8, "file-read", "file-read-data", "/Users/dev/My Docs/x/.env"),
		fakeDenialLine(t, 8, "file-read", "file-read-data", "/Users/dev/Old Docs/x/.env"),
		fakeSentinelLine(t, "end"),
	}

	entries, complete := startFakeStream(t, lines, true).end(false)
	assert.True(t, complete)
	assert.Len(t, entries, 4)
}

// A dropped signal denial makes the stream incomplete for every run. A
// dropped noise denial matters only to a failed run, which reports noise. An
// incomplete stream sends the run to the log store, so the dropped denial is
// not lost.
func TestSeatbeltLogStreamDroppedEntryMakesItIncomplete(t *testing.T) {
	overflow := func(kind, operation, operand string) []string {
		lines := []string{fakeSentinelLine(t, "start")}
		for i := 0; i <= seatbeltStreamEntryCap; i++ {
			lines = append(lines, fakeDenialLine(t, 7, kind, operation, fmt.Sprintf(operand, i)))
		}
		return append(lines, fakeSentinelLine(t, "end"))
	}
	ruleReads := overflow("file-read", "file-read-data", "/secret/%d")
	catchAllWrites := overflow(seatbeltKindDefault, "file-write-data", "/Users/dev/.config/%d")
	sysctlReads := overflow(seatbeltKindDefault, "sysctl-read", "kern.noise%d")

	tests := []struct {
		name         string
		lines        []string
		withNoise    bool
		wantComplete bool
		wantEntries  int
	}{
		{name: "rule denials fill the signal buffer, clean run", lines: ruleReads, wantEntries: seatbeltStreamEntryCap},
		{name: "rule denials fill the signal buffer, failed run", lines: ruleReads, withNoise: true, wantEntries: seatbeltStreamEntryCap},
		{name: "catch-all writes fill the signal buffer, clean run", lines: catchAllWrites, wantEntries: seatbeltStreamEntryCap},
		{name: "noise fills the noise buffer, clean run", lines: sysctlReads, wantComplete: true, wantEntries: 0},
		{name: "noise fills the noise buffer, failed run", lines: sysctlReads, withNoise: true, wantEntries: seatbeltStreamEntryCap},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entries, complete := startFakeStream(t, tc.lines, true).end(tc.withNoise)
			assert.Equal(t, tc.wantComplete, complete)
			assert.Len(t, entries, tc.wantEntries)
		})
	}
}

// A failed run reports every denial, catch-all ones too, each as the kernel
// logged it, as it did before the stream existed.
func TestSeatbeltFailedRunReportsEveryDenial(t *testing.T) {
	st := startFakeStream(t, []string{
		fakeSentinelLine(t, "start"),
		strings.Replace(fakeDenialLine(t, 7, "file-read", "file-read-data", "/Users/dev/.netrc"), "node(7)", "git(7)", 1),
		fakeDenialLine(t, 8, "file-read", "file-read-data", "/Users/dev/.netrc"),
		fakeDenialLine(t, 7, seatbeltKindDefault, "file-write-data", "/dev/dtracehelper"),
		fakeDenialLine(t, 8, seatbeltKindDefault, "file-write-data", "/dev/dtracehelper"),
		fakeSentinelLine(t, "end"),
	}, true)

	report, err := fakeSeatbeltSandbox(st).BestEffortViolation(errors.New("exit status 1"))
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.Len(t, report.Violations, 4)
}

// The log store entries stay as they are, so a failed run reports what it
// reported before the stream existed. The stream adds only what the store
// does not have yet, and an event that both report counts once.
func TestMergeSeatbeltEntries(t *testing.T) {
	entry := func(line string) seatbeltLogEntry {
		var e seatbeltLogEntry
		require.NoError(t, json.Unmarshal([]byte(line), &e))
		return e
	}
	a := entry(fakeDenialLine(t, 7, "file-read", "file-read-data", "/a"))
	b := entry(fakeDenialLine(t, 7, "file-read", "file-read-data", "/b"))
	c := entry(fakeDenialLine(t, 7, "file-read", "file-read-data", "/c"))

	tests := []struct {
		name     string
		streamed []seatbeltLogEntry
		stored   []seatbeltLogEntry
		want     []seatbeltLogEntry
	}{
		{name: "store only", stored: []seatbeltLogEntry{a, a, b}, want: []seatbeltLogEntry{a, a, b}},
		{name: "stream only", streamed: []seatbeltLogEntry{a, b}, want: []seatbeltLogEntry{a, b}},
		{name: "both report the same events", streamed: []seatbeltLogEntry{a, b}, stored: []seatbeltLogEntry{a, b}, want: []seatbeltLogEntry{a, b}},
		{name: "store does not have one yet", streamed: []seatbeltLogEntry{a, c}, stored: []seatbeltLogEntry{a, b}, want: []seatbeltLogEntry{a, b, c}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, mergeSeatbeltEntries(tc.streamed, tc.stored))
		})
	}
}

// An incomplete stream still delivered real denials. The run keeps them when
// the log store does not have them yet.
func TestSeatbeltIncompleteStreamKeepsCapturedDenial(t *testing.T) {
	requireSandboxExec(t)

	st := startFakeStream(t, []string{
		fakeSentinelLine(t, "start"),
		fakeDenialLine(t, 8, "file-read", "file-read-data", "/Users/dev/.ssh/id_rsa"),
	}, false)

	report, err := fakeSeatbeltSandbox(st).BestEffortViolation(nil)
	require.NoError(t, err)
	require.NotNil(t, report, "a denial that the stream delivered must not be lost")
	assert.Contains(t, violationTargets(report), "/Users/dev/.ssh/id_rsa")
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

// A sandboxed process can write a log entry with the run marker, and it can
// read the run tag from the profile. The reader takes only kernel entries, so
// a fake end sentinel does not end the stream early, and a fake denial is not
// a violation.
func TestSeatbeltLogStreamIgnoresUserSpaceEntries(t *testing.T) {
	logger := "/usr/bin/logger"
	fakeDenial := strings.Replace(fakeDenialLine(t, 9, "file-read", "file-read-data", "/Users/dev/.forged"), seatbeltKernelImagePath, logger, 1)

	cmd := fakeLogStream(printLines(fakeSentinelLine(t, "start"), fakeSentinelLineFrom(t, logger, "end"), fakeDenial) +
		`sleep 0.3; ` +
		printLines(fakeDenialLine(t, 8, "file-read", "file-read-data", "/Users/dev/.ssh/id_rsa"), fakeSentinelLine(t, "end")) +
		`exec sleep 30`)
	st, err := startSeatbeltLogStream(cmd, fakeStreamTag, fakeStreamNonce, noopSentinel, time.Second)
	require.NoError(t, err)
	t.Cleanup(st.shutdown)

	report, err := fakeSeatbeltSandbox(st).BestEffortViolation(nil)
	require.NoError(t, err)
	require.NotNil(t, report, "the denial after the fake end sentinel must not be lost")
	assert.Equal(t, []string{"/Users/dev/.ssh/id_rsa"}, violationTargets(report))
}

// The log store path drops the entries that the kernel did not write too.
func TestKernelEntries(t *testing.T) {
	kernel := seatbeltLogEntry{EventMessage: "a", ProcessImagePath: seatbeltKernelImagePath}
	logger := seatbeltLogEntry{EventMessage: "b", ProcessImagePath: "/usr/bin/logger"}
	unknown := seatbeltLogEntry{EventMessage: "c"}

	assert.Equal(t, []seatbeltLogEntry{kernel}, kernelEntries([]seatbeltLogEntry{logger, kernel, unknown}))
}

// The real sentinel must reach a real log stream.
func TestTriggerSeatbeltSentinelReachesLogStream(t *testing.T) {
	requireSandboxExec(t)

	tag := generateLogTag()
	st, err := startSeatbeltLogStream(seatbeltLogStreamCommand(tag), tag, newSentinelNonce(), triggerSeatbeltSentinel, seatbeltStreamReadyTimeout)
	require.NoError(t, err)

	_, complete := st.end(false)
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
