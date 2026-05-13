//go:build !windows

package pty

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestInputRouterReadLoopContextStopsOnCancelForFileReader(t *testing.T) {
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	defer func() {
		require.NoError(t, reader.Close())
	}()
	defer func() {
		require.NoError(t, writer.Close())
	}()

	router, err := NewInputRouter(&bytes.Buffer{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		router.ReadLoopContext(ctx, reader)
	}()

	cancel()

	require.Eventually(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
}

func TestInputRouterReadLoopContextStopsOnWriteError(t *testing.T) {
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	defer func() {
		require.NoError(t, reader.Close())
	}()
	defer func() {
		require.NoError(t, writer.Close())
	}()

	router, err := NewInputRouter(errorWriter{})
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		router.ReadLoopContext(context.Background(), reader)
	}()

	_, err = writer.Write([]byte("x"))
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
}

type errorWriter struct{}

func (errorWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write failed")
}
