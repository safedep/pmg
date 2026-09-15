//go:build windows

package ptyx

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Keep a real child alive after TerminateProcess by giving the session a
// handle without termination rights. The test retains a handle for cleanup.
func spawnUnterminatedSession(t *testing.T, attached bool) (*winSession, windows.Handle) {
	t.Helper()
	con, err := NewConPty(80, 25, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	mode := "gated"
	if attached {
		mode = "flood"
	}
	env := buildEnvBlock(append(os.Environ(), "PTYX_DRAIN_MODE="+mode, "PTYX_DRAIN_READY="+ready, "PTYX_DRAIN_GATE="+filepath.Join(dir, "gate")))
	line, err := windows.UTF16PtrFromString(buildCommandLine(os.Args[0], []string{"-test.run=^TestWinDrainHelper$"}))
	if err != nil {
		t.Fatal(err)
	}
	si := windows.StartupInfoEx{}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	if attached {
		si.ProcThreadAttributeList = con.attrList.List()
	} else {
		flags |= windows.CREATE_NO_WINDOW
	}
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(nil, line, nil, nil, false, flags, &env[0], nil, &si.StartupInfo, &pi); err != nil {
		_ = con.Close()
		t.Fatal(err)
	}
	var process windows.Handle
	access := uint32(windows.SYNCHRONIZE | windows.PROCESS_QUERY_LIMITED_INFORMATION)
	if err := windows.DuplicateHandle(windows.CurrentProcess(), pi.Process, windows.CurrentProcess(), &process, access, false, 0); err != nil {
		_ = windows.TerminateProcess(pi.Process, 99)
		_ = windows.CloseHandle(pi.Process)
		_ = windows.CloseHandle(pi.Thread)
		_ = con.Close()
		t.Fatal(err)
	}
	s := &winSession{
		con: con, stdin: con.inFile, stdout: con.outFile,
		process: process, thread: pi.Thread, pid: int(pi.ProcessId),
		done: make(chan struct{}), waitDone: make(chan struct{}),
	}
	go s.waitProcess(process)
	t.Cleanup(func() {
		_ = windows.TerminateProcess(pi.Process, 99)
		go io.Copy(io.Discard, s.PtyReader())
		_ = s.Close()
		_ = s.Wait()
		_ = windows.CloseHandle(pi.Process)
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			return s, pi.Process
		}
		if time.Now().After(deadline) {
			t.Fatal("helper did not become ready")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWinSession_CloseBeforeExit(t *testing.T) {
	s, process := spawnUnterminatedSession(t, false)
	waitHandle := s.process
	go io.Copy(io.Discard, s.PtyReader())
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
		status, err := windows.WaitForSingleObject(process, 0)
		if err != nil || status != uint32(windows.WAIT_TIMEOUT) {
			t.Fatalf("child must still be alive: status=%d err=%v", status, err)
		}
		if pid, err := windows.GetProcessId(waitHandle); err != nil || pid != uint32(s.Pid()) {
			t.Fatalf("Close released the waiter's handle before exit: pid=%d err=%v", pid, err)
		}
		select {
		case <-s.waitDone:
			t.Fatal("Wait completed before the child exited")
		default:
		}
	case <-time.After(time.Second):
		_ = windows.TerminateProcess(process, 99)
		select {
		case <-closed:
		case <-time.After(3 * time.Second):
			t.Fatal("Close remained blocked after terminating the helper")
		}
		t.Fatal("Close waited for the child to exit after console cleanup completed")
	}
	_ = windows.TerminateProcess(process, 99)
	var exitErr *ExitError
	if err := s.Wait(); !errors.As(err, &exitErr) || exitErr.ExitCode != 99 {
		t.Fatalf("Wait lost the exit status after Close: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if pid, err := windows.GetProcessId(waitHandle); err != nil || pid != uint32(s.Pid()) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("deferred cleanup did not release the process handle after exit")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWinSession_KillTimeoutWhileDraining(t *testing.T) {
	s, _ := spawnUnterminatedSession(t, true)
	// Back up output before the reader calls Kill and resumes draining.
	time.Sleep(200 * time.Millisecond)
	drained := make(chan struct{})
	killed := make(chan error, 1)
	reader := s.PtyReader()
	go func() {
		killed <- s.Kill()
		_, _ = io.Copy(io.Discard, reader)
		close(drained)
	}()
	select {
	case err := <-killed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		// Rescue the reader so a regression fails without hanging the suite.
		go io.Copy(io.Discard, reader)
		select {
		case <-killed:
		case <-time.After(3 * time.Second):
			t.Fatal("Kill remained blocked after rescue output draining started")
		}
		t.Fatal("Kill waited for output that its caller could not drain")
	}
	select {
	case <-drained:
	case <-time.After(3 * time.Second):
		t.Fatal("console cleanup did not finish after Kill returned")
	}
}

func TestConPty_ResizeAfterClose(t *testing.T) {
	con, err := NewConPty(80, 25, 0)
	if err != nil {
		t.Fatal(err)
	}
	go io.Copy(io.Discard, con.outFile)
	if err := con.Close(); err != nil {
		t.Fatal(err)
	}
	if *con.hpc != 0 {
		t.Fatal("Close retained a freed pseudoconsole handle")
	}
	if err := con.resize(100, 30); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Resize after Close = %v, want os.ErrClosed", err)
	}
}

func TestConPty_ConcurrentResizeAndClose(t *testing.T) {
	con, err := NewConPty(80, 25, 0)
	if err != nil {
		t.Fatal(err)
	}
	go io.Copy(io.Discard, con.outFile)
	var workers sync.WaitGroup
	started := make(chan struct{}, 4)
	for worker := 0; worker < 4; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			started <- struct{}{}
			for i := 0; i < 100; i++ {
				if err := con.resize(80+i%20, 25); err != nil {
					if !errors.Is(err, os.ErrClosed) {
						t.Errorf("Resize during cleanup: %v", err)
					}
					return
				}
			}
		}()
	}
	for worker := 0; worker < 4; worker++ {
		<-started
	}
	if err := con.Close(); err != nil {
		t.Error(err)
	}
	workers.Wait()
}
