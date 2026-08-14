package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultCIEndpointID(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "no CI detected returns empty",
			env: map[string]string{
				"GITHUB_ACTIONS": "",
			},
			want: "",
		},
		{
			name: "hosted github actions derives repository-scoped identity",
			env: map[string]string{
				"GITHUB_ACTIONS":     "true",
				"GITHUB_RUN_ID":      "12345",
				"GITHUB_REPOSITORY":  "safedep/pmg",
				"RUNNER_ENVIRONMENT": "github-hosted",
			},
			want: "gh:safedep/pmg",
		},
		{
			name: "self-hosted runner keeps the host identity",
			env: map[string]string{
				"GITHUB_ACTIONS":     "true",
				"GITHUB_RUN_ID":      "12345",
				"GITHUB_REPOSITORY":  "safedep/pmg",
				"RUNNER_ENVIRONMENT": "self-hosted",
			},
			want: "",
		},
		{
			name: "hosted github actions without repository returns empty",
			env: map[string]string{
				"GITHUB_ACTIONS":     "true",
				"GITHUB_RUN_ID":      "12345",
				"GITHUB_REPOSITORY":  "",
				"RUNNER_ENVIRONMENT": "github-hosted",
			},
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for key, value := range tc.env {
				t.Setenv(key, value)
			}

			assert.Equal(t, tc.want, defaultCIEndpointID())
		})
	}
}
