//go:build windows

package ptyx

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ConPty struct {
	mu            sync.Mutex
	hpc           *windows.Handle
	inR_hostWrite windows.Handle
	outR_hostRead windows.Handle
	inFile        *os.File
	outFile       *os.File
	attrList      *windows.ProcThreadAttributeListContainer
	size          windows.Coord
	closeOnce     sync.Once
}

func NewConPty(w, h int, flags uint32) (c *ConPty, err error) {
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 25
	}

	c = &ConPty{
		hpc:  new(windows.Handle),
		size: windows.Coord{X: int16(w), Y: int16(h)},
	}

	var ptyInRead, ptyOutWrite windows.Handle

	if err = windows.CreatePipe(&ptyInRead, &c.inR_hostWrite, nil, 0); err != nil {
		return nil, fmt.Errorf("failed to create input pipe for pseudo console: %w", err)
	}

	if err = windows.CreatePipe(&c.outR_hostRead, &ptyOutWrite, nil, 0); err != nil {
		return nil, fmt.Errorf("failed to create output pipe for pseudo console: %w", err)
	}

	if err = windows.SetHandleInformation(c.inR_hostWrite, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		return nil, fmt.Errorf("failed to set handle information for input pipe: %w", err)
	}

	if err = windows.SetHandleInformation(c.outR_hostRead, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		return nil, fmt.Errorf("failed to set handle information for output pipe: %w", err)
	}

	err = windows.CreatePseudoConsole(c.size, ptyInRead, ptyOutWrite, flags, c.hpc)
	if err != nil {
		return nil, fmt.Errorf("failed to create pseudo console: %w", err)
	}

	if err := windows.CloseHandle(ptyInRead); err != nil {
		return nil, fmt.Errorf("failed to close pseudo console handle: %w", err)
	}
	if err := windows.CloseHandle(ptyOutWrite); err != nil {
		return nil, fmt.Errorf("failed to close pseudo console handle: %w", err)
	}

	c.inFile = os.NewFile(uintptr(c.inR_hostWrite), "conpty-stdin")
	c.outFile = os.NewFile(uintptr(c.outR_hostRead), "conpty-stdout")

	c.attrList, err = windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, fmt.Errorf("failed to create proc thread attribute list: %w", err)
	}

	err = c.attrList.Update(
		windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
		unsafe.Pointer(*c.hpc),
		unsafe.Sizeof(*c.hpc),
	)

	if err != nil {
		c.attrList.Delete()
		return nil, fmt.Errorf("failed to update proc thread attributes: %w", err)
	}

	return c, nil
}

func (c *ConPty) ClosePty() {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		var hpc windows.Handle
		if c.hpc != nil {
			hpc = *c.hpc
			*c.hpc = 0
		}
		c.mu.Unlock()
		if hpc != 0 {
			windows.ClosePseudoConsole(hpc)
		}
	})
}

func (c *ConPty) Close() error {
	c.ClosePty()
	if c.attrList != nil {
		c.attrList.Delete()
		c.attrList = nil
	}
	var e1, e2 error
	if c.inFile != nil {
		e1 = c.inFile.Close()
		c.inFile = nil
	}
	if c.outFile != nil {
		e2 = c.outFile.Close()
		c.outFile = nil
	}
	if e1 != nil && !errors.Is(e1, os.ErrClosed) {
		return e1
	}
	if errors.Is(e2, os.ErrClosed) {
		return nil
	}
	return e2
}

func (c *ConPty) resize(w, h int) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hpc == nil || *c.hpc == 0 {
		return os.ErrClosed
	}
	c.size = windows.Coord{X: int16(w), Y: int16(h)}
	return windows.ResizePseudoConsole(*c.hpc, c.size)
}
