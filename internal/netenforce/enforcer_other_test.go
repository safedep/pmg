//go:build !linux

package netenforce

import (
	"errors"
	"testing"

	"github.com/safedep/pmg/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewIsUnsupportedOffLinux(t *testing.T) {
	e, err := New()
	require.Error(t, err)
	assert.Nil(t, e)
	assert.ErrorIs(t, err, ErrUnsupported)
	assert.Contains(t, err.Error(), platform.OSName())
	var ue *unsupportedError
	assert.True(t, errors.As(err, &ue))
}
