//go:build windows

package pty

import (
	"context"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

var procAllocConsole = kernel32.NewProc("AllocConsole")

// consoleInput opens the console input buffer of this process in raw mode
// with an empty buffer. A test process on a CI runner has no console, so it
// allocates one first. AllocConsole fails when a console already exists, and
// the CONIN$ open then works on that one.
func consoleInput(t *testing.T) (*os.File, windows.Handle) {
	t.Helper()
	require.NoError(t, procAllocConsole.Find())
	if r1, _, err := procAllocConsole.Call(); r1 == 0 {
		t.Logf("AllocConsole: %v (a console may already exist)", err)
	}

	name, err := windows.UTF16PtrFromString("CONIN$")
	require.NoError(t, err)
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	require.NoError(t, err, "no console input on this runner, so the wake path is unproven here")

	var mode uint32
	require.NoError(t, windows.GetConsoleMode(handle, &mode))
	raw := mode &^ (windows.ENABLE_ECHO_INPUT | windows.ENABLE_PROCESSED_INPUT | windows.ENABLE_LINE_INPUT)
	require.NoError(t, windows.SetConsoleMode(handle, raw))
	require.NoError(t, windows.FlushConsoleInputBuffer(handle))

	file := os.NewFile(uintptr(handle), "CONIN$")
	t.Cleanup(func() {
		assert.NoError(t, windows.SetConsoleMode(handle, mode))
		assert.NoError(t, file.Close())
	})
	return file, handle
}

// INPUT_RECORD is 20 bytes: a WORD, two bytes of padding, and a 16-byte
// KEY_EVENT_RECORD. A wrong layout writes a record Windows misreads.
func TestInputRecordMatchesWin32Layout(t *testing.T) {
	assert.Equal(t, uintptr(20), unsafe.Sizeof(inputRecord{}))
	assert.Equal(t, uintptr(4), unsafe.Offsetof(inputRecord{}.event))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(keyEventRecord{}.controlKeyState))
}

func pendingEvents(t *testing.T, handle windows.Handle) uint32 {
	t.Helper()
	var n uint32
	require.NoError(t, windows.GetNumberOfConsoleInputEvents(handle, &n))
	return n
}

type readResult struct {
	n   int
	err error
	buf []byte
}

func readAsync(ctx context.Context, src *os.File) <-chan readResult {
	out := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 64)
		n, err := readInput(ctx, src, buf)
		out <- readResult{n: n, err: err, buf: buf[:n]}
	}()
	return out
}

func awaitRead(t *testing.T, results <-chan readResult) readResult {
	t.Helper()
	select {
	case r := <-results:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("readInput did not return; the console read was not woken")
		return readResult{}
	}
}

// A read parked on the console returns once ctx ends, and it leaves no key
// behind for the shell that started pmg.
func TestReadInputCancelWakesConsoleRead(t *testing.T) {
	file, handle := consoleInput(t)
	ctx, cancel := context.WithCancel(context.Background())
	results := readAsync(ctx, file)

	time.Sleep(50 * time.Millisecond)
	cancel()

	got := awaitRead(t, results)
	assert.ErrorIs(t, got.err, context.Canceled)
	assert.Zero(t, got.n)
	assert.Zero(t, pendingEvents(t, handle), "the wake key must not stay in the buffer")
}

// A key typed before ctx ends reaches the caller unchanged.
func TestReadInputDeliversTypedKey(t *testing.T) {
	file, handle := consoleInput(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := readAsync(ctx, file)

	time.Sleep(50 * time.Millisecond)
	require.NoError(t, writeConsoleKey(handle, 'a'))

	got := awaitRead(t, results)
	require.NoError(t, got.err)
	assert.Equal(t, "a", string(got.buf))
	assert.Zero(t, pendingEvents(t, handle))
}

// A key and the cancellation that land in the same instant race the watcher.
// Whichever wins, the read returns, and the wake key never stays behind. The
// only event that may remain is the typed key, when it arrived after the wake
// key had already returned the read.
func TestReadInputRaceLeavesNoWakeKeyBehind(t *testing.T) {
	file, handle := consoleInput(t)

	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		results := readAsync(ctx, file)
		time.Sleep(10 * time.Millisecond)

		go cancel()
		require.NoError(t, writeConsoleKey(handle, 'a'))

		got := awaitRead(t, results)
		switch {
		case got.err == nil:
			assert.Equal(t, "a", string(got.buf), "iteration %d", i)
			assert.Zero(t, pendingEvents(t, handle), "iteration %d left a key in the buffer", i)
		default:
			assert.ErrorIs(t, got.err, context.Canceled, "iteration %d", i)
			if pendingEvents(t, handle) > 0 {
				buf := make([]byte, 64)
				n, err := file.Read(buf)
				require.NoError(t, err)
				assert.Equal(t, "a", string(buf[:n]), "iteration %d: only the typed key may remain", i)
			}
			assert.Zero(t, pendingEvents(t, handle), "iteration %d left a key in the buffer", i)
		}
		require.NoError(t, windows.FlushConsoleInputBuffer(handle))
	}
}
