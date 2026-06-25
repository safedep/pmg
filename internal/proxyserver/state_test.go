package proxyserver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteAndReadState(t *testing.T) {
	dir := t.TempDir()
	path := stateFilePath(dir)

	s := State{PID: 12345, Addr: "127.0.0.1:9999", CACertPath: "/tmp/ca.pem"}
	require.NoError(t, writeState(path, s))

	got, err := readState(path)
	require.NoError(t, err)
	assert.Equal(t, s.PID, got.PID)
	assert.Equal(t, s.Addr, got.Addr)
	assert.Equal(t, s.CACertPath, got.CACertPath)
}

func TestWriteStateCreatesMissingDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "proxy-state.json")
	require.NoError(t, writeState(path, State{PID: 1, Addr: "127.0.0.1:1"}))

	got, err := readState(path)
	require.NoError(t, err)
	assert.Equal(t, 1, got.PID)
}

func TestReadStateMissingFile(t *testing.T) {
	_, err := readState(filepath.Join(t.TempDir(), "nonexistent.json"))
	assert.Error(t, err)
}

func TestRemoveState(t *testing.T) {
	dir := t.TempDir()
	path := stateFilePath(dir)

	require.NoError(t, writeState(path, State{PID: 1, Addr: "127.0.0.1:1"}))
	require.NoError(t, removeState(path))

	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}

func TestIsRunningCurrentProcess(t *testing.T) {
	s := State{PID: os.Getpid(), Addr: "127.0.0.1:1"}
	assert.True(t, s.IsRunning())
}

func TestIsRunningDeadPID(t *testing.T) {
	s := State{PID: 999999999}
	assert.False(t, s.IsRunning())
}

func TestStateFilePath(t *testing.T) {
	assert.Equal(t, "/some/dir/proxy-state.json", stateFilePath("/some/dir"))
}

func TestResolveStatePath(t *testing.T) {
	t.Run("flag override wins", func(t *testing.T) {
		assert.Equal(t, "/custom/proxy.json", ResolveStatePath("/custom/proxy.json", "/cache"))
	})

	t.Run("defaults to cacheDir", func(t *testing.T) {
		assert.Equal(t, filepath.Join("/cache", "proxy-state.json"), ResolveStatePath("", "/cache"))
	})
}
