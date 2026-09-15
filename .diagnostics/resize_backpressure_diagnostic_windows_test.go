//go:build windows

package ptyx

import (
	"context"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestWinSession_ResizeBackpressureDiagnostic is a temporary native diagnostic.
// Copy this file alongside session_drain_windows_test.go and run:
//
//	go test -run '^TestWinSession_ResizeBackpressureDiagnostic$' -v -count=1 -timeout=45s
//
// Run the same diagnostic on each revision, without -race: the older revision
// already races on ConPty.size when multiple callers resize, which is separate
// from the native control-pipe/shutdown dependency investigated here.
//
// The worker is isolated because spawnDrainSession registers an unbounded Close
// cleanup. A test-local timeout cannot bound that cleanup if native rescue fails.
func TestWinSession_ResizeBackpressureDiagnostic(t *testing.T) {
	const workerEnv = "PTYX_RESIZE_BACKPRESSURE_DIAGNOSTIC_WORKER"
	if os.Getenv(workerEnv) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0],
			"-test.run=^TestWinSession_ResizeBackpressureDiagnostic$", "-test.v")
		cmd.Env = append(os.Environ(), workerEnv+"=1")
		cmd.WaitDelay = time.Second
		output, err := cmd.CombinedOutput()
		t.Logf("isolated native diagnostic:\n%s", output)
		if ctx.Err() != nil {
			t.Fatalf("diagnostic exceeded its 30s watchdog; worker was terminated: %v", ctx.Err())
		}
		if err != nil {
			t.Fatalf("diagnostic worker failed: %v", err)
		}
		return
	}

	build := windows.RtlGetVersion().BuildNumber
	t.Logf("Windows build=%d; ClosePseudoConsole is normally nonblocking from build 26100", build)
	control := runResizeBackpressureDiagnosticCase(t, "without-resizes", false)
	resizing := runResizeBackpressureDiagnosticCase(t, "with-resizes", true)

	if !resizing.resizeStalled {
		t.Log("INCONCLUSIVE: did not observe a sustained outstanding resize before Close")
		return
	}
	if !control.closeBeforeDrain {
		if build < 26100 {
			t.Log("INCONCLUSIVE: the control Close also needed output drain, as expected on older Windows")
		} else {
			t.Log("INCONCLUSIVE: the control Close also needed output drain on this host")
		}
		return
	}
	if !resizing.closeBeforeDrain {
		t.Errorf("Close completed before output drain without resizes, but required rescue with a stalled resize; compare this observation across revisions")
		return
	}
	t.Log("NOT REPRODUCED: Close completed before rescue even with a sustained outstanding resize")
}

type resizeBackpressureDiagnosticObservation struct {
	resizeStalled    bool
	closeBeforeDrain bool
}

func runResizeBackpressureDiagnosticCase(t *testing.T, label string, resize bool) resizeBackpressureDiagnosticObservation {
	t.Helper()
	s, _ := spawnDrainSession(t, "flood")
	reader := s.PtyReader()

	stop := make(chan struct{})
	var stopOnce sync.Once
	stopResizes := func() { stopOnce.Do(func() { close(stop) }) }
	type drainResult struct {
		bytes int64
		err   error
	}
	drained := make(chan drainResult, 1)
	var drainOnce sync.Once
	startDrain := func() {
		drainOnce.Do(func() {
			go func() {
				n, err := io.Copy(io.Discard, reader)
				drained <- drainResult{bytes: n, err: err}
			}()
		})
	}
	// Registered after spawnDrainSession's cleanup, so rescue begins first if
	// this diagnostic fails before reaching its normal rescue phase.
	t.Cleanup(func() {
		stopResizes()
		startDrain()
	})

	process, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(s.Pid()))
	if err != nil {
		t.Fatalf("%s: open helper process for observation: %v", label, err)
	}
	defer windows.CloseHandle(process)

	// The helper publishes readiness before starting its write loop. Let its
	// output back up before making any resize or shutdown call.
	time.Sleep(350 * time.Millisecond)
	var issued, completed, resizeErrors atomic.Int64
	pumpsDone := make(chan struct{})
	observation := resizeBackpressureDiagnosticObservation{}
	if resize {
		const workers = 4
		const callsPerWorker = 8192
		var wg sync.WaitGroup
		wg.Add(workers)
		for worker := 0; worker < workers; worker++ {
			go func(worker int) {
				defer wg.Done()
				for i := 0; i < callsPerWorker; i++ {
					select {
					case <-stop:
						return
					default:
					}
					issued.Add(1)
					err := s.Resize(80+(i+worker)%8, 25+(i+worker)%4)
					completed.Add(1)
					if err != nil {
						resizeErrors.Add(1)
						return
					}
				}
			}(worker)
		}
		go func() {
			wg.Wait()
			close(pumpsDone)
		}()

		// This is evidence of a stall, not proof of a native stack location.
		// Native stacks or ETW are needed to distinguish a blocked WriteFile
		// from severe scheduling delays on a heavily loaded machine.
		ticker := time.NewTicker(50 * time.Millisecond)
		deadline := time.NewTimer(3 * time.Second)
		lastCompleted := completed.Load()
		lastProgress := time.Now()
	observe:
		for {
			select {
			case <-pumpsDone:
				break observe
			case now := <-ticker.C:
				current := completed.Load()
				if current != lastCompleted {
					lastCompleted = current
					lastProgress = now
				}
				if current > 0 && issued.Load() > current && now.Sub(lastProgress) >= 350*time.Millisecond {
					observation.resizeStalled = true
					break observe
				}
			case <-deadline.C:
				break observe
			}
		}
		ticker.Stop()
		deadline.Stop()
	} else {
		close(pumpsDone)
	}

	// Leave existing native calls outstanding, but prevent a resize loop from
	// deliberately continuing to use the old HPCON after shutdown completes.
	stopResizes()
	if issued.Load() == completed.Load() {
		observation.resizeStalled = false
	}
	t.Logf("%s: before Close: issued=%d completed=%d resize-errors=%d stalled=%v",
		label, issued.Load(), completed.Load(), resizeErrors.Load(), observation.resizeStalled)

	type closeResult struct {
		err     error
		elapsed time.Duration
	}
	closed := make(chan closeResult, 1)
	go func() {
		started := time.Now()
		err := s.Close()
		closed <- closeResult{err: err, elapsed: time.Since(started)}
	}()
	var closeOutcome closeResult
	select {
	case closeOutcome = <-closed:
		observation.closeBeforeDrain = true
	case <-time.After(2 * time.Second):
	}
	status, statusErr := windows.WaitForSingleObject(process, 0)
	t.Logf("%s: before rescue: close-returned=%v child-status=%d child-status-error=%v issued=%d completed=%d",
		label, observation.closeBeforeDrain, status, statusErr, issued.Load(), completed.Load())

	// Every path starts a reader, including modern Windows where Close may
	// already have closed the stream. The latter can legitimately yield ErrClosed.
	startDrain()
	if !observation.closeBeforeDrain {
		select {
		case closeOutcome = <-closed:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: Close did not finish within 5s of rescue; outer worker watchdog bounds cleanup", label)
		}
	}
	t.Logf("%s: Close elapsed=%v error=%v", label, closeOutcome.elapsed, closeOutcome.err)
	if closeOutcome.err != nil {
		t.Errorf("%s: Close returned an error: %v", label, closeOutcome.err)
	}
	select {
	case <-pumpsDone:
	case <-time.After(3 * time.Second):
		t.Errorf("%s: resize calls remained blocked after Close and rescue", label)
	}
	select {
	case result := <-drained:
		t.Logf("%s: rescue bytes=%d error=%v; final issued=%d completed=%d resize-errors=%d",
			label, result.bytes, result.err, issued.Load(), completed.Load(), resizeErrors.Load())
	case <-time.After(3 * time.Second):
		t.Errorf("%s: rescue reader did not finish after Close", label)
	}
	return observation
}
