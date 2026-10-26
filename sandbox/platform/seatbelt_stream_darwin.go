//go:build darwin

package platform

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox"
)

const (
	// seatbeltStreamReadyTimeout bounds the wait for the start sentinel. A
	// stream that does not deliver it is not used.
	seatbeltStreamReadyTimeout = 2 * time.Second

	// seatbeltStreamEndTimeout bounds the wait for the end sentinel. A stream
	// that does not deliver it is incomplete, and the run reads the log store.
	seatbeltStreamEndTimeout = 2 * time.Second

	// seatbeltSentinelRetry is how often a sentinel is made again while PMG
	// waits for it. A sentinel made before the stream is attached is lost.
	seatbeltSentinelRetry = 100 * time.Millisecond

	// seatbeltStreamEntryCap bounds each of the two buffers of one run: the
	// signal denials, and the noise denials that sandbox.IsNoise selects. A
	// failed `go build` makes more than 2000 denials, so a cap of 512 filled
	// and sent ordinary runs to the slow log store. A dedup of the entries
	// saved space but merged separate denials, such as one file read by two
	// programs. A larger cap keeps every denial and uses a few MB at most.
	seatbeltStreamEntryCap = 8192

	seatbeltStreamStopTimeout = 2 * time.Second

	// seatbeltKindSentinel marks the denials that PMG makes itself to confirm
	// that the stream delivers. They are never violations.
	seatbeltKindSentinel = "sentinel"

	// seatbeltSentinelPath exists on every Mac and every user can read it, so
	// a denied read of it always reaches the log.
	seatbeltSentinelPath = "/private/etc/hosts"
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

// seatbeltSentinelTrigger makes a denial that carries the sentinel marker of
// logTag and target.
type seatbeltSentinelTrigger func(logTag, target string) error

// seatbeltLogStream collects the unified log entries of one run while the
// command runs. A query of the log store after the run misses a denial that
// has not reached the store yet, and each query costs about 0.7s or more.
//
// The kernel logs the denials in order. So when a sentinel denial that PMG
// makes after the command exits comes through the stream, every denial of the
// command came through before it.
//
// Only the kernel writes a denial, so the reader takes only kernel entries. A
// sandboxed process can write any other log entry, and it can read the run
// tag from the profile. Each sentinel target also carries a random value that
// the process never sees.
type seatbeltLogStream struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	done  chan struct{}

	logTag     string
	nonce      string
	trigger    seatbeltSentinelTrigger
	endTimeout time.Duration
	arrived    chan struct{}

	mu sync.Mutex
	// signalEntries and noiseEntries are separate, so noise cannot push out
	// a signal denial.
	signalEntries []seatbeltLogEntry
	noiseEntries  []seatbeltLogEntry
	signalDropped bool
	noiseDropped  bool
	sentinels     map[string]bool
}

// seatbeltStreamCommand runs argv under seatbeltStreamWrapper, in a process
// group of its own, so shutdown can kill the wrapper, the watcher and the
// stream together.
func seatbeltStreamCommand(argv ...string) *exec.Cmd {
	cmd := exec.Command("/bin/sh", append([]string{"-c", seatbeltStreamWrapper, "sh"}, argv...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

func seatbeltLogStreamCommand(logTag string) *exec.Cmd {
	return seatbeltStreamCommand(macOSUnifiedLogPath, "stream",
		"--style", "ndjson",
		"--predicate", seatbeltRunPredicate(logTag))
}

// triggerSeatbeltSentinel runs a denied read of seatbeltSentinelPath under a
// one-rule profile, so the kernel logs a denial with the sentinel marker.
func triggerSeatbeltSentinel(logTag, target string) error {
	profile := fmt.Sprintf(`(version 1)(allow default)(deny file-read-data (literal "%s") (with message "%s"))`,
		seatbeltSentinelPath, seatbeltLogMessage(logTag, seatbeltKindSentinel, target))

	err := exec.Command(seatbeltSandboxExecPath, "-p", profile, "/bin/cat", seatbeltSentinelPath).Run()

	// cat fails on the denied read, as intended.
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return nil
	}
	if err == nil {
		return errors.New("the sentinel read was not denied")
	}

	return fmt.Errorf("run the sentinel: %w", err)
}

// newSentinelNonce returns the random value that the sentinel targets of one
// stream carry.
func newSentinelNonce() string {
	return rand.Text()[:8]
}

// startSeatbeltLogStream starts cmd and returns when a start sentinel came
// through it, so the stream is attached. It stops cmd and returns an error
// when the start sentinel does not come in readyTimeout. cmd must come from
// seatbeltStreamCommand.
func startSeatbeltLogStream(cmd *exec.Cmd, logTag, nonce string, trigger seatbeltSentinelTrigger, readyTimeout time.Duration) (*seatbeltLogStream, error) {
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

	st := &seatbeltLogStream{
		cmd:        cmd,
		stdin:      stdin,
		done:       make(chan struct{}),
		logTag:     logTag,
		nonce:      nonce,
		trigger:    trigger,
		endTimeout: seatbeltStreamEndTimeout,
		arrived:    make(chan struct{}, 1),
		sentinels:  make(map[string]bool),
	}
	go st.read(stdout)

	if !st.confirm("start", readyTimeout) {
		st.shutdown()
		return nil, errors.New("log stream did not deliver the start sentinel")
	}

	return st, nil
}

// read buffers the denials of the run and notes the sentinels. Lines that are
// not JSON, such as the header, entries that the kernel did not write, and
// entries of other runs are skipped.
func (st *seatbeltLogStream) read(r io.Reader) {
	defer close(st.done)

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		var entry seatbeltLogEntry
		if err := json.Unmarshal(bytes.TrimSpace(scanner.Bytes()), &entry); err != nil || !entry.fromKernel() {
			continue
		}

		payload, ok := parseSeatbeltLogPayload(entry.EventMessage)
		if !ok || payload.RunID != st.logTag {
			continue
		}

		if payload.Kind == seatbeltKindSentinel {
			st.mu.Lock()
			st.sentinels[payload.Target] = true
			st.mu.Unlock()

			select {
			case st.arrived <- struct{}{}:
			default:
			}
			continue
		}

		st.keep(entry)
	}

	if err := scanner.Err(); err != nil {
		log.Debugf("seatbelt log stream read: %v", err)
	}
}

// keep buffers a denial as signal or noise, by the rule that a clean run
// reports by. When that buffer is full, keep notes the drop, so the run can
// read the log store for the rest.
func (st *seatbeltLogStream) keep(entry seatbeltLogEntry) {
	noise := slices.ContainsFunc(extractSeatbeltViolations([]seatbeltLogEntry{entry}, st.logTag), func(v sandbox.Violation) bool {
		return sandbox.IsNoise(sandbox.DriverSeatbelt, v)
	})

	st.mu.Lock()
	defer st.mu.Unlock()

	buffer, dropped := &st.signalEntries, &st.signalDropped
	if noise {
		buffer, dropped = &st.noiseEntries, &st.noiseDropped
	}

	if len(*buffer) < seatbeltStreamEntryCap {
		*buffer = append(*buffer, entry)
		return
	}

	if !*dropped {
		*dropped = true
		log.Debugf("seatbelt log stream: buffer full (%d), dropping further entries", seatbeltStreamEntryCap)
	}
}

// confirm makes the sentinel of phase until it comes through the stream, and
// reports whether it came in timeout.
func (st *seatbeltLogStream) confirm(phase string, timeout time.Duration) bool {
	target := phase + "-" + st.nonce
	if err := st.trigger(st.logTag, target); err != nil {
		log.Debugf("seatbelt log stream sentinel: %v", err)
		return false
	}

	retry := time.NewTicker(seatbeltSentinelRetry)
	defer retry.Stop()
	deadline := time.After(timeout)

	for {
		if st.hasSentinel(target) {
			return true
		}

		select {
		case <-st.arrived:
		case <-retry.C:
			if err := st.trigger(st.logTag, target); err != nil {
				log.Debugf("seatbelt log stream sentinel: %v", err)
				return false
			}
		case <-st.done:
			return st.hasSentinel(target)
		case <-deadline:
			return false
		}
	}
}

func (st *seatbeltLogStream) hasSentinel(target string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.sentinels[target]
}

// end confirms that every denial made before the call came through the
// stream, then stops it. The run reports noise denials only when withNoise is
// true, so only then does a dropped noise denial matter.
// complete is false when the stream ended early, did not deliver the end
// sentinel, or dropped a denial that the run reports. The entries are real
// denials in every case.
func (st *seatbeltLogStream) end(withNoise bool) (entries []seatbeltLogEntry, complete bool) {
	delivered := st.confirm("end", st.endTimeout)
	st.shutdown()

	st.mu.Lock()
	defer st.mu.Unlock()

	entries = append([]seatbeltLogEntry(nil), st.signalEntries...)
	dropped := st.signalDropped
	if withNoise {
		entries = append(entries, st.noiseEntries...)
		dropped = dropped || st.noiseDropped
	}

	return entries, delivered && !dropped
}

// shutdown stops the stream. The wrapper ends it when its standard input
// closes.
func (st *seatbeltLogStream) shutdown() {
	if err := st.stdin.Close(); err != nil {
		log.Debugf("close seatbelt log stream input: %v", err)
	}

	select {
	case <-st.done:
	case <-time.After(seatbeltStreamStopTimeout):
		log.Debugf("seatbelt log stream did not end after its input closed, killing its process group")
		if err := syscall.Kill(-st.cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			log.Debugf("kill seatbelt log stream process group: %v", err)
		}

		// Wait closes the output pipe, so let the reader finish first.
		select {
		case <-st.done:
		case <-time.After(seatbeltStreamStopTimeout):
			log.Debugf("seatbelt log stream output did not close after the kill")
		}
	}

	// The wrapper exits with the status of the stream, which is a signal
	// after a stop. That is not an error.
	if err := st.cmd.Wait(); err != nil {
		log.Debugf("seatbelt log stream exit: %v", err)
	}
}
