package pty

import (
	"bytes"
	"io"
	"sync"
	"sync/atomic"
)

// OutputRouter manages buffered vs live output.
type OutputRouter struct {
	mu        sync.Mutex
	stdout    io.Writer
	buffer    bytes.Buffer
	buffering bool
}

func NewOutputRouter(out io.Writer) (*OutputRouter, error) {
	return &OutputRouter{
		stdout: out,
	}, nil
}

func (r *OutputRouter) Write(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.buffering {
		// We are in "Prompt Mode", so save this output for later.
		// If we printed it now, it would mess up the confirmation prompt.
		return r.buffer.Write(p)
	}

	// Normal mode: just print it to stdout.
	return r.stdout.Write(p)
}

// Pause starts buffering output. Call this before showing a confirmation prompt.
func (r *OutputRouter) Pause() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buffering = true
}

// Resume stops buffering, flushes any buffered output, and resumes live output.
// Call this after the confirmation prompt is complete.
func (r *OutputRouter) Resume() {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Flush any buffered output
	if r.buffer.Len() > 0 {
		_, _ = io.Copy(r.stdout, &r.buffer)
		r.buffer.Reset()
	}

	r.buffering = false
}

// writerDest wraps io.Writer for use with atomic.Pointer
// (atomic.Value panics on nil interface stores)
type writerDest struct {
	w io.Writer
}

// InputRouter manages routing stdin to either PTY or a prompt pipe.
// Only ONE goroutine should call ReadLoop().
type InputRouter struct {
	dest       atomic.Pointer[writerDest]
	defaultDst io.Writer // PTY writer
}

func NewInputRouter(ptyWriter io.Writer) (*InputRouter, error) {
	return &InputRouter{
		defaultDst: ptyWriter,
	}, nil
}

// ReadLoop continuously reads from src and routes to current destination.
// Call this in a goroutine. Exits when src returns error (EOF).
func (r *InputRouter) ReadLoop(src io.Reader) {
	buf := make([]byte, 1024)
	for {
		nr, err := src.Read(buf)
		if err != nil {
			return
		}

		// Check where to route the data
		if dest := r.dest.Load(); dest != nil {
			// Send confirmation prompt response to the pipe. (PMG)
			_, _ = dest.w.Write(buf[:nr])
		} else {
			// Send response to the child PTY.
			_, _ = r.defaultDst.Write(buf[:nr])
		}
	}
}

// RouteToPrompt switches input to go to the given writer (prompt pipe)
func (r *InputRouter) RouteToPrompt(w io.Writer) {
	r.dest.Store(&writerDest{w: w})
}

// RouteToPTY switches input back to the PTY (default)
func (r *InputRouter) RouteToPTY() {
	r.dest.Store(nil)
}
