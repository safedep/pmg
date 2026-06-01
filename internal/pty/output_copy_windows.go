//go:build windows

package pty

import (
	"context"
	"io"
)

// copyPTYOutput on Windows uses a plain context-aware copy. The conpty backend
// is not affected by the kqueue netpoller issue that requires a poll(2) loop on
// unix hosts.
func copyPTYOutput(ctx context.Context, dst io.Writer, src io.Reader) error {
	return copyWithContext(ctx, dst, src)
}
