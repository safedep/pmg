//go:build !windows

package pty

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const ptyPollTimeoutMs = 100

// copyPTYOutput copies child output from the PTY master to dst, driving the
// read with a manual poll(2) loop instead of relying on Go's kqueue-based
// netpoller.
//
// On some hardened / MDM-managed macOS hosts the runtime cannot register the
// PTY master with the netpoller. os.OpenFile then leaves the master in
// non-blocking mode without poller backing, so a plain io.Copy read returns
// raw EAGAIN ("resource temporarily unavailable") on the very first read.
// Forcing the master into blocking mode is not an option either: on macOS a
// concurrent Close() does not interrupt a blocked PTY read(), leaking the
// reader goroutine and its OS thread. poll(2) sidesteps both: it works without
// the netpoller and the timeout lets us honor ctx cancellation without ever
// depending on Close() to unblock a read.
func copyPTYOutput(ctx context.Context, dst io.Writer, src io.Reader) error {
	file, ok := src.(*os.File)
	if !ok {
		return copyWithContext(ctx, dst, src)
	}

	fd := int32(file.Fd())
	pollFds := []unix.PollFd{{Fd: fd, Events: unix.POLLIN}}
	buf := make([]byte, outputCopyBufferSize)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		n, err := unix.Poll(pollFds, ptyPollTimeoutMs)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("failed to poll pty master: %w", err)
		}

		if n == 0 {
			continue // timeout: loop back to re-check ctx
		}

		revents := pollFds[0].Revents

		// Drain readable data before acting on a hangup so that output written
		// just before the child exited (POLLIN and POLLHUP can be reported
		// together) is not lost.
		if revents&unix.POLLIN != 0 {
			nr, rerr := file.Read(buf)
			if nr > 0 {
				nw, werr := dst.Write(buf[:nr])
				if werr != nil {
					return werr
				}
				if nw < nr {
					return io.ErrShortWrite
				}
			}
			if rerr != nil {
				if isReadEOF(rerr) {
					return nil
				}
				if errors.Is(rerr, unix.EAGAIN) {
					continue
				}
				return rerr
			}
			continue
		}

		if revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return nil
		}
	}
}

// isReadEOF reports whether a read error signals end of stream on the PTY
// master. The master surfaces the child closing the slave as io.EOF on darwin
// and as EIO on Linux.
func isReadEOF(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, unix.EIO)
}
