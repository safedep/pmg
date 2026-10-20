//go:build darwin

package platform

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/safedep/dry/log"
)

const (
	// seatbeltStreamReadyTimeout bounds the wait for the first line of log
	// stream. The stream prints that line when it is attached, so it catches
	// every denial after the line.
	seatbeltStreamReadyTimeout = 2 * time.Second

	// seatbeltStreamDrainWait is how long a run waits after the command exits
	// for denials that are still on their way to the stream.
	seatbeltStreamDrainWait = 150 * time.Millisecond

	// seatbeltStreamEntryCap bounds the buffer of one run. The predicate
	// matches only the denials of that run.
	seatbeltStreamEntryCap = 512

	seatbeltStreamStopTimeout = 2 * time.Second
)

// seatbeltStreamWrapper runs its arguments until its standard input closes.
// pmg holds the only write end of that pipe, so the stream also ends when pmg
// dies, even by SIGKILL. When the stream ends on its own, the wrapper stops
// the watcher, so the watcher cannot later signal a reused PID, then exits
// with the status of the stream. An asynchronous list reads /dev/null as its
// standard input, so the watcher uses a copy of it on file descriptor 3.
const seatbeltStreamWrapper = `exec 3<&0
"$@" </dev/null 3<&- &
pid=$!
{ read -r _ <&3; kill "$pid" 2>/dev/null; } >/dev/null 2>&1 &
watcher=$!
wait "$pid"
status=$?
kill "$watcher" 2>/dev/null
exit "$status"`

// seatbeltLogStream collects the unified log entries of one run while the
// command runs. A query of the log store after the run misses a denial that
// has not reached the store yet, and each query costs about 0.7s or more.
type seatbeltLogStream struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	done  chan struct{}

	mu      sync.Mutex
	entries []seatbeltLogEntry
}

// seatbeltStreamCommand runs argv under seatbeltStreamWrapper.
func seatbeltStreamCommand(argv ...string) *exec.Cmd {
	return exec.Command("/bin/sh", append([]string{"-c", seatbeltStreamWrapper, "sh"}, argv...)...)
}

func seatbeltLogStreamCommand(logTag string) *exec.Cmd {
	return seatbeltStreamCommand(macOSUnifiedLogPath, "stream",
		"--style", "ndjson",
		"--predicate", seatbeltRunPredicate(logTag))
}

// startSeatbeltLogStream starts cmd and returns when the stream is attached.
// It stops cmd and returns an error when the stream ends or is not ready in
// readyTimeout. cmd must come from seatbeltStreamCommand.
func startSeatbeltLogStream(cmd *exec.Cmd, readyTimeout time.Duration) (*seatbeltLogStream, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("pipe log stream input: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("pipe log stream output: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start log stream: %w", err)
	}

	st := &seatbeltLogStream{cmd: cmd, stdin: stdin, done: make(chan struct{})}
	ready := make(chan struct{})
	go st.read(stdout, ready)

	select {
	case <-ready:
		return st, nil
	case <-st.done:
		st.stop(0)
		return nil, errors.New("log stream ended before it was ready")
	case <-time.After(readyTimeout):
		st.stop(0)
		return nil, errors.New("log stream was not ready in time")
	}
}

// read buffers the entries of the stream. The first line is the plain-text
// header that log stream prints when it is attached. Lines that are not JSON
// are status lines and are skipped.
func (st *seatbeltLogStream) read(r io.Reader, ready chan<- struct{}) {
	defer close(st.done)

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	attached := false
	dropped := false
	for scanner.Scan() {
		if !attached {
			attached = true
			close(ready)
			continue
		}

		var entry seatbeltLogEntry
		if err := json.Unmarshal(bytes.TrimSpace(scanner.Bytes()), &entry); err != nil {
			continue
		}

		st.mu.Lock()
		if len(st.entries) < seatbeltStreamEntryCap {
			st.entries = append(st.entries, entry)
		} else if !dropped {
			dropped = true
			log.Warnf("seatbelt log stream: entry buffer full (%d), dropping further entries", seatbeltStreamEntryCap)
		}
		st.mu.Unlock()
	}

	if err := scanner.Err(); err != nil {
		log.Debugf("seatbelt log stream read: %v", err)
	}
}

// stop waits drain for late entries, then ends the stream and returns what it
// collected. complete is false when the stream ended before stop, so it can
// miss entries.
func (st *seatbeltLogStream) stop(drain time.Duration) (entries []seatbeltLogEntry, complete bool) {
	select {
	case <-st.done:
	case <-time.After(drain):
	}

	// A separate check, because a select picks at random when the stream has
	// ended and the drain has also run out.
	complete = true
	select {
	case <-st.done:
		complete = false
	default:
	}

	// The wrapper ends the stream when its standard input closes.
	if err := st.stdin.Close(); err != nil {
		log.Debugf("close seatbelt log stream input: %v", err)
	}

	select {
	case <-st.done:
	case <-time.After(seatbeltStreamStopTimeout):
		log.Debugf("seatbelt log stream did not end after its input closed, killing the wrapper")
		if err := st.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			log.Debugf("kill seatbelt log stream wrapper: %v", err)
		}
	}

	// The wrapper exits with the status of the stream, which is a signal
	// after a stop. That is not an error.
	if err := st.cmd.Wait(); err != nil {
		log.Debugf("seatbelt log stream exit: %v", err)
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	return append([]seatbeltLogEntry(nil), st.entries...), complete
}
