package pty

import (
	"context"
	"errors"
	"io"
)

const outputCopyBufferSize = 32 * 1024

// copyWithContext is a plain context-aware copy used as a fallback when the
// source is not a *os.File (e.g. mocks in tests) and on platforms without a
// poll-based reader. Cancellation is observed between reads.
func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) error {
	buf := make([]byte, outputCopyBufferSize)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		nr, err := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if werr != nil {
				return werr
			}
			if nw < nr {
				return io.ErrShortWrite
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}
