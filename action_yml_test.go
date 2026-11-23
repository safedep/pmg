package main

import (
	"os"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The runner refuses an action.yml that does not parse, and then every job
// that uses the action fails before its first step. No other test loads the
// file as the runner does.
func TestActionYAMLLoads(t *testing.T) {
	data, err := os.ReadFile("action.yml")
	require.NoError(t, err)

	var action struct {
		Name        string                    `yaml:"name"`
		Description string                    `yaml:"description"`
		Inputs      map[string]map[string]any `yaml:"inputs"`
		Outputs     map[string]map[string]any `yaml:"outputs"`
		Runs        map[string]any            `yaml:"runs"`
	}
	require.NoError(t, yaml.Unmarshal(data, &action))

	assert.NotEmpty(t, action.Name)
	assert.NotEmpty(t, action.Description)
	assert.Equal(t, "action/main.js", action.Runs["main"])
	assert.Equal(t, "action/post.js", action.Runs["post"])
	require.NotEmpty(t, action.Inputs)
	for _, section := range []map[string]map[string]any{action.Inputs, action.Outputs} {
		for name, field := range section {
			description, ok := field["description"].(string)
			assert.Truef(t, ok && description != "", "%s has no string description", name)
		}
	}
}
