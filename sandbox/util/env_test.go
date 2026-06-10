package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScrubEnv(t *testing.T) {
	tests := []struct {
		name        string
		env         []string
		opts        EnvScrubOptions
		wantKept    []string
		wantRemoved []string
	}{
		{
			name:        "built-in deny scrubs known secret",
			env:         []string{"PATH=/usr/bin", "AWS_SECRET_ACCESS_KEY=abc"},
			wantKept:    []string{"PATH=/usr/bin"},
			wantRemoved: []string{"AWS_SECRET_ACCESS_KEY"},
		},
		{
			name:        "case-insensitive match",
			env:         []string{"aws_secret_access_key=abc"},
			wantKept:    []string{},
			wantRemoved: []string{"aws_secret_access_key"},
		},
		{
			name:        "allow suppresses built-in deny",
			env:         []string{"NPM_TOKEN=secret"},
			opts:        EnvScrubOptions{Allow: []string{"NPM_TOKEN"}},
			wantKept:    []string{"NPM_TOKEN=secret"},
			wantRemoved: nil,
		},
		{
			name:        "profile deny glob scrubs",
			env:         []string{"MY_CUSTOM_TOKEN=x", "OTHER=y"},
			opts:        EnvScrubOptions{Deny: []string{"*_TOKEN"}},
			wantKept:    []string{"OTHER=y"},
			wantRemoved: []string{"MY_CUSTOM_TOKEN"},
		},
		{
			name:        "allow glob wins over profile deny glob",
			env:         []string{"npm_config_registry=x", "npm_config_token=y"},
			opts:        EnvScrubOptions{Deny: []string{"*_TOKEN", "npm_config_*"}, Allow: []string{"npm_config_*"}},
			wantKept:    []string{"npm_config_registry=x", "npm_config_token=y"},
			wantRemoved: nil,
		},
		{
			name:        "protected essential never scrubbed even under broad deny",
			env:         []string{"PATH=/usr/bin", "HOME=/home/u", "LC_ALL=en_US.UTF-8"},
			opts:        EnvScrubOptions{Deny: []string{"*"}},
			wantKept:    []string{"PATH=/usr/bin", "HOME=/home/u", "LC_ALL=en_US.UTF-8"},
			wantRemoved: nil,
		},
		{
			name:        "non-sensitive variables are kept",
			env:         []string{"FOO=bar", "EDITOR=vim"},
			wantKept:    []string{"FOO=bar", "EDITOR=vim"},
			wantRemoved: nil,
		},
		{
			name:        "entry without equals is treated as a name",
			env:         []string{"GITHUB_TOKEN", "PLAINNAME"},
			wantKept:    []string{"PLAINNAME"},
			wantRemoved: []string{"GITHUB_TOKEN"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScrubEnv(tt.env, tt.opts)
			assert.Equal(t, tt.wantKept, got.Env)
			assert.Equal(t, tt.wantRemoved, got.Removed)
		})
	}
}

func TestScrubEnv_RemovesEntirelyNotBlanked(t *testing.T) {
	got := ScrubEnv([]string{"GITHUB_TOKEN=secret"}, EnvScrubOptions{})

	require.Empty(t, got.Env)
	assert.NotContains(t, got.Env, "GITHUB_TOKEN=")
	assert.Equal(t, []string{"GITHUB_TOKEN"}, got.Removed)
}

func TestScrubEnv_NoCatchAllsInBuiltinList(t *testing.T) {
	// A novel token name must NOT be scrubbed by the default list (catch-alls
	// are opt-in per profile, never built in).
	got := ScrubEnv([]string{"SOME_RANDOM_TOKEN=x"}, EnvScrubOptions{})

	assert.Equal(t, []string{"SOME_RANDOM_TOKEN=x"}, got.Env)
	assert.Empty(t, got.Removed)
}
