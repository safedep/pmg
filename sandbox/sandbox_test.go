package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExecutionResultScrubbedEnvCount(t *testing.T) {
	r := NewExecutionResult()
	assert.Equal(t, 0, r.ScrubbedEnvCount())

	r.SetScrubbedEnvCount(3)
	assert.Equal(t, 3, r.ScrubbedEnvCount())
}

func TestExecutionResultScrubbedEnvCountNilReceiver(t *testing.T) {
	var r *ExecutionResult
	assert.Equal(t, 0, r.ScrubbedEnvCount())
}
