package ptyx

import (
	"context"
	"io"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestDiagnosticCancelAfterClose(t *testing.T) {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	prog := filepath.Join(dir, "cmd.exe")
	line, err := windows.UTF16PtrFromString(`"` + prog + `" /d /c exit 0`)
	if err != nil {
		t.Fatal(err)
	}
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	victim := new(windows.ProcessInformation)
	if err := windows.CreateProcess(nil, line, nil, nil, false, windows.CREATE_SUSPENDED, nil, nil, &startup, victim); err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(victim.Thread)
	defer windows.CloseHandle(victim.Process)
	defer windows.TerminateProcess(victim.Process, 99)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session, err := Spawn(ctx, SpawnOpts{Prog: prog, Args: []string{"/d", "/c", "exit", "0"}, Cols: 80, Rows: 25})
	if err != nil {
		t.Fatal(err)
	}
	oldHandle := session.(*winSession).process
	oldPID := session.Pid()
	drained := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, session.PtyReader())
		close(drained)
	}()
	if err := session.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	<-drained

	var aliases []windows.Handle
	defer func() {
		for _, handle := range aliases {
			windows.CloseHandle(handle)
		}
	}()
	reused := false
	for i := 0; i < 16384; i++ {
		var alias windows.Handle
		if err := windows.DuplicateHandle(windows.CurrentProcess(), victim.Process, windows.CurrentProcess(), &alias, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
			t.Fatal(err)
		}
		aliases = append(aliases, alias)
		if alias == oldHandle {
			reused = true
			break
		}
	}
	if !reused {
		t.Fatal("Could not reproduce handle reuse")
	}
	currentPID, err := windows.GetProcessId(oldHandle)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Closed session PID %d handle %d now refers to unrelated suspended PID %d", oldPID, oldHandle, currentPID)
	status, err := windows.WaitForSingleObject(victim.Process, 100)
	if err != nil || status != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("Victim must be alive before cancellation: status=%d err=%v", status, err)
	}
	cancel()
	status, err = windows.WaitForSingleObject(victim.Process, 3000)
	if err != nil {
		t.Fatal(err)
	}
	if status == windows.WAIT_OBJECT_0 {
		var code uint32
		if err := windows.GetExitCodeProcess(victim.Process, &code); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("CONFIRMED: cancel after Close killed unrelated PID %d through reused handle %d, exit code %d", currentPID, oldHandle, code)
	}
	t.Log("Unrelated process survived cancellation")
}
