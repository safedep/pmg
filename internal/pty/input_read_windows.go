//go:build windows

package pty

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"unsafe"

	"github.com/safedep/dry/log"
	"golang.org/x/sys/windows"
)

// wakeKey is the character the watcher writes to the console input buffer to
// return a pending read. It sits in the Unicode private use area, so it never
// collides with a key a developer can type.
const wakeKey = "\uE000"

var (
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procWriteConsoleInputW = kernel32.NewProc("WriteConsoleInputW")
)

// readInput reads from src and returns ctx.Err() once ctx ends. A read on a
// console handle cannot be cancelled, so a watcher writes one wake key to the
// console input buffer when ctx ends. The pending read returns with that key,
// readInput drops it, and the caller sees the cancellation. The caller must
// hold the console in raw mode, because a line-mode read returns only on
// Enter.
//
// A source that is not a console gets a plain read. A pipe ends with EOF and
// the loop above checks ctx between reads.
func readInput(ctx context.Context, src io.Reader, buf []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	handle, ok := consoleInputHandle(src)
	if !ok {
		return src.Read(buf)
	}

	readDone := make(chan struct{})
	woken := make(chan bool, 1)
	go func() {
		select {
		case <-ctx.Done():
			woken <- wakeConsoleRead(handle)
		case <-readDone:
			woken <- false
		}
	}()

	n, err := src.Read(buf)
	close(readDone)

	if <-woken && !bytes.Contains(buf[:n], []byte(wakeKey)) {
		consumeWakeKey(src)
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return 0, ctxErr
	}
	return n, err
}

// consumeWakeKey reads the console until the wake key has passed. It runs
// when a read returned typed input in the same instant ctx ended, so the wake
// key is still in the console buffer behind that input. Left there, the shell
// that started pmg receives it as a keystroke after pmg exits. Each read
// returns at once, because the wake key is in the buffer and nothing else
// reads the console. The bound only guards against a flood of typed keys.
func consumeWakeKey(src io.Reader) {
	buf := make([]byte, 64)
	for range 16 {
		n, err := src.Read(buf)
		if err != nil {
			log.Warnf("failed to consume the console wake key: %v", err)
			return
		}
		if bytes.Contains(buf[:n], []byte(wakeKey)) {
			return
		}
	}
	log.Warnf("console wake key not found behind typed input, it may reach the shell")
}

// consoleInputHandle returns the console handle behind src, when src is a
// console. A pipe or a file has no console mode.
func consoleInputHandle(src io.Reader) (windows.Handle, bool) {
	file, ok := src.(*os.File)
	if !ok {
		return 0, false
	}
	handle := windows.Handle(file.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return 0, false
	}
	return handle, true
}

// keyEventRecord mirrors KEY_EVENT_RECORD.
type keyEventRecord struct {
	keyDown         int32
	repeatCount     uint16
	virtualKeyCode  uint16
	virtualScanCode uint16
	unicodeChar     uint16
	controlKeyState uint32
}

// inputRecord mirrors INPUT_RECORD with a KEY_EVENT payload.
type inputRecord struct {
	eventType uint16
	_         uint16
	event     keyEventRecord
}

const keyEvent = 0x0001

// wakeConsoleRead writes one wake key press to the console input buffer and
// reports whether the write succeeded.
func wakeConsoleRead(handle windows.Handle) bool {
	if err := writeConsoleKey(handle, []rune(wakeKey)[0]); err != nil {
		log.Warnf("failed to wake the console read: %v", err)
		return false
	}
	return true
}

// writeConsoleKey writes one key press for r to the console input buffer.
// x/sys/windows has no wrapper for WriteConsoleInputW, so the call goes
// through kernel32 directly.
func writeConsoleKey(handle windows.Handle, r rune) error {
	// Find keeps Call from panicking on a build with no console API.
	if err := procWriteConsoleInputW.Find(); err != nil {
		return err
	}

	record := inputRecord{
		eventType: keyEvent,
		event: keyEventRecord{
			keyDown:     1,
			repeatCount: 1,
			unicodeChar: uint16(r),
		},
	}
	var written uint32
	r1, _, callErr := procWriteConsoleInputW.Call(uintptr(handle),
		uintptr(unsafe.Pointer(&record)), 1, uintptr(unsafe.Pointer(&written)))
	// LazyProc.Call is not the syscall form the compiler recognises, so the
	// pointers need an explicit hold until the call returns.
	runtime.KeepAlive(&record)
	runtime.KeepAlive(&written)
	if r1 == 0 {
		return callErr
	}
	if written != 1 {
		return fmt.Errorf("wrote %d console input records, want 1", written)
	}
	return nil
}
