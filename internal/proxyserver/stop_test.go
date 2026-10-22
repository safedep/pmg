package proxyserver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStopWithoutStateIsErrNoProxy(t *testing.T) {
	_, err := Stop(filepath.Join(t.TempDir(), "state.json"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoProxy)
}

func TestStopWithUnreadableStateIsNotErrNoProxy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0o600))

	_, err := Stop(path)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNoProxy)
}
