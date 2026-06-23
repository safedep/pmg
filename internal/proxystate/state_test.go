package proxystate_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/internal/proxystate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteAndRead(t *testing.T) {
	dir := t.TempDir()
	path := proxystate.StatePath(dir)

	s := proxystate.State{PID: 12345, Addr: "127.0.0.1:9999", CACertPath: "/tmp/ca.pem"}
	require.NoError(t, proxystate.Write(path, s))

	got, err := proxystate.Read(path)
	require.NoError(t, err)
	assert.Equal(t, s.PID, got.PID)
	assert.Equal(t, s.Addr, got.Addr)
	assert.Equal(t, s.CACertPath, got.CACertPath)
}

func TestReadMissingFile(t *testing.T) {
	_, err := proxystate.Read(filepath.Join(t.TempDir(), "nonexistent.json"))
	assert.Error(t, err)
}

func TestRemove(t *testing.T) {
	dir := t.TempDir()
	path := proxystate.StatePath(dir)

	require.NoError(t, proxystate.Write(path, proxystate.State{PID: 1, Addr: "127.0.0.1:1"}))
	require.NoError(t, proxystate.Remove(path))

	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}

func TestIsRunningCurrentProcess(t *testing.T) {
	s := proxystate.State{PID: os.Getpid(), Addr: "127.0.0.1:1"}
	assert.True(t, s.IsRunning())
}

func TestIsRunningDeadPID(t *testing.T) {
	s := proxystate.State{PID: 999999999}
	assert.False(t, s.IsRunning())
}

func TestStatePath(t *testing.T) {
	path := proxystate.StatePath("/some/config/dir")
	assert.Equal(t, "/some/config/dir/proxy-state.json", path)
}
