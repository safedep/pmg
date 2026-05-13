//go:build windows

package pty

import (
	"context"
	"io"
)

func readInput(ctx context.Context, src io.Reader, buf []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
		return src.Read(buf)
	}
}
