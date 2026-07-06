package shim

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBinaryNotFoundError(t *testing.T) {
	err := &BinaryNotFoundError{Name: "bun"}

	assert.Equal(t, "bun is not installed", err.Error())
	assert.Equal(t, commandNotFoundExitCode, err.ExitCode())
}
