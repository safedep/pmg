//go:build !windows

package pty

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/safedep/ptyx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func spawnSh(t *testing.T, script string) ptyx.Session {
	t.Helper()
	sess, err := ptyx.Spawn(context.Background(), ptyx.SpawnOpts{
		Prog: "/bin/sh",
		Args: []string{"-c", script},
		Cols: 80,
		Rows: 24,
		Env:  os.Environ(),
	})
	require.NoError(t, err)
	return sess
}

func TestCopyPTYOutput_DataAndEOF(t *testing.T) {
	sess := spawnSh(t, "printf 'hello-pty-output'")
	defer func() { _ = sess.Close() }()

	var buf bytes.Buffer
	err := copyPTYOutput(context.Background(), &buf, sess.PtyReader())
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "hello-pty-output")
	_ = sess.Wait()
}

// TestCopyPTYOutput_CancelDoesNotHang guards the core invariant: a reader
// blocked with no data available must return promptly on cancellation, never
// relying on Close() to interrupt a blocked read (which does not work on macOS).
func TestCopyPTYOutput_CancelDoesNotHang(t *testing.T) {
	sess := spawnSh(t, "sleep 10")
	defer func() { _ = sess.Close() }()
	defer func() { _ = sess.Kill() }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- copyPTYOutput(ctx, io.Discard, sess.PtyReader()) }()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("copyPTYOutput did not return after cancel: goroutine/thread leak")
	}
}

// TestCopyPTYOutput_FallbackNonFile exercises the copyWithContext path used for
// readers that are not *os.File (e.g. test doubles).
func TestCopyPTYOutput_FallbackNonFile(t *testing.T) {
	pr, pw := io.Pipe()
	var buf bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- copyPTYOutput(context.Background(), &buf, pr) }()

	_, err := pw.Write([]byte("piped-data"))
	require.NoError(t, err)
	require.NoError(t, pw.Close())

	require.NoError(t, <-done)
	assert.Equal(t, "piped-data", buf.String())
}
