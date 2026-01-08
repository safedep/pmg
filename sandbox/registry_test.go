package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDefaultProfileRegistry(t *testing.T) {
	registry, err := newDefaultProfileRegistry()
	assert.NoError(t, err)
	assert.NotNil(t, registry)

	assert.Greater(t, len(registry.profiles), 0)

	npmRestrictive, err := registry.GetProfile("npm-restrictive")
	assert.NoError(t, err)
	assert.NotNil(t, npmRestrictive)

	pypiRestrictive, err := registry.GetProfile("pypi-restrictive")
	assert.NoError(t, err)
	assert.NotNil(t, pypiRestrictive)
}
