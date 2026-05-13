//go:build !windows

package pty

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func readInput(ctx context.Context, src io.Reader, buf []byte) (int, error) {
	file, ok := src.(*os.File)
	if !ok {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
			return src.Read(buf)
		}
	}

	fd := int32(file.Fd())
	pollFds := []unix.PollFd{{Fd: fd, Events: unix.POLLIN}}

	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}

		n, err := unix.Poll(pollFds, 100)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}

			return 0, err
		}

		if n == 0 {
			continue
		}

		revents := pollFds[0].Revents
		if revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return 0, io.EOF
		}

		if revents&unix.POLLIN != 0 {
			return file.Read(buf)
		}
	}
}
