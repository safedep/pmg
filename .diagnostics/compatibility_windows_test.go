//go:build windows

package ptyx

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestReviewHelper(t *testing.T) {
	mode := os.Getenv("PTYX_REVIEW_MODE")
	if mode == "" {
		return
	}
	if err := os.WriteFile(os.Getenv("PTYX_REVIEW_READY"), []byte("ready"), 0600); err != nil {
		os.Exit(2)
	}
	switch mode {
	case "flood":
		for {
			if _, err := fmt.Fprintln(os.Stdout, strings.Repeat("output", 100)); err != nil {
				os.Exit(3)
			}
		}
	case "gated":
		for {
			if _, err := os.Stat(os.Getenv("PTYX_REVIEW_GATE")); err == nil {
				os.Exit(0)
			}
			time.Sleep(time.Millisecond)
		}
	}
}

func reviewSpawn(t *testing.T, mode string) (Session, string) {
	t.Helper()
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	gate := filepath.Join(dir, "gate")
	s, err := Spawn(context.Background(), SpawnOpts{
		Prog: os.Args[0],
		Args: []string{"-test.run=^TestReviewHelper$"},
		Env:  append(os.Environ(), "PTYX_REVIEW_MODE="+mode, "PTYX_REVIEW_READY="+ready, "PTYX_REVIEW_GATE="+gate),
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			return s, gate
		}
		if time.Now().After(deadline) {
			_ = s.Close()
			t.Fatal("helper did not become ready")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestReviewCloseStdinAfterClose(t *testing.T) {
	s, gate := reviewSpawn(t, "gated")
	drained := make(chan struct{})
	reader := s.PtyReader()
	go func() { _, _ = io.Copy(io.Discard, reader); close(drained) }()
	if err := os.WriteFile(gate, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	<-drained
	if err := s.CloseStdin(); err != nil {
		t.Fatalf("CloseStdin after Close changed from a no-op to an error: %v", err)
	}
}

func TestReviewCloseAfterStdinEOF(t *testing.T) {
	s, gate := reviewSpawn(t, "gated")
	drained := make(chan struct{})
	reader := s.PtyReader()
	go func() { _, _ = io.Copy(io.Discard, reader); close(drained) }()
	if err := s.CloseStdin(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gate, nil, 0600); err != nil {
		t.Fatal(err)
	}
	waitErr := s.Wait()
	<-drained
	// Let the automatic console cleanup finish before the explicit Close.
	time.Sleep(100 * time.Millisecond)
	closeErr := s.Close()
	t.Logf("Wait=%v Close=%v", waitErr, closeErr)
	if closeErr != nil {
		t.Fatalf("Close reports an already-closed stdin as a cleanup failure: %v", closeErr)
	}
}

func TestReviewKillFromOutputReaderDuringClose(t *testing.T) {
	s, _ := reviewSpawn(t, "flood")
	reader := s.PtyReader()
	process, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(s.Pid()))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(process)
	// Leave the output pipe backed up while Close shuts down the console.
	time.Sleep(200 * time.Millisecond)
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	status, err := windows.WaitForSingleObject(process, 3000)
	if err != nil || status != windows.WAIT_OBJECT_0 {
		go io.Copy(io.Discard, reader)
		t.Fatalf("Close did not terminate the helper: status=%d err=%v", status, err)
	}
	select {
	case <-closed:
		t.Skip("ClosePseudoConsole returned without waiting for output drain on this Windows version")
	case <-time.After(100 * time.Millisecond):
	}
	drained := make(chan struct{})
	go func() {
		_ = s.Kill()
		_, _ = io.Copy(io.Discard, reader)
		close(drained)
	}()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
		<-drained
	case <-time.After(2 * time.Second):
		// A second reader breaks the deadlock so the test can clean up.
		rescued := make(chan struct{})
		go func() { _, _ = io.Copy(io.Discard, reader); close(rescued) }()
		select {
		case <-closed:
		case <-time.After(3 * time.Second):
			t.Fatal("Close remained blocked after rescue reader started")
		}
		<-drained
		<-rescued
		t.Fatal("Close holds the session lock while waiting for output, so the reader blocks in Kill before it can drain")
	}
}
