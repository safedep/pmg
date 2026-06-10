package sandbox

import (
	"testing"

	"github.com/safedep/pmg/sandbox/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProfileEnvContract pins the env protection contract as a regression
// test: npm-restrictive and pypi-restrictive are pure bases that allow
// nothing, each package manager's leaf profile re-allows only its own auth
// variables (plus the shared config conventions of its ecosystem), and
// sibling tokens stay scrubbed alongside other ecosystems' and cloud
// credentials.
func TestProfileEnvContract(t *testing.T) {
	r, err := newDefaultProfileRegistry()
	require.NoError(t, err)

	env := []string{
		"NPM_TOKEN=x",
		"NODE_AUTH_TOKEN=x",
		"YARN_NPM_AUTH_TOKEN=x",
		"BUN_AUTH_TOKEN=x",
		"TWINE_PASSWORD=x",
		"UV_PUBLISH_TOKEN=x",
		"POETRY_PYPI_TOKEN_PYPI=x",
		"AWS_SECRET_ACCESS_KEY=x",
		"GITHUB_TOKEN=x",
		"OP_SERVICE_ACCOUNT_TOKEN=x",
		"CLOUDFLARE_API_TOKEN=x",
	}

	tests := []struct {
		profile      string
		wantKept     []string
		wantScrubbed []string
	}{
		{
			profile:      "npm-restrictive",
			wantKept:     []string{},
			wantScrubbed: []string{"NPM_TOKEN", "NODE_AUTH_TOKEN", "YARN_NPM_AUTH_TOKEN", "BUN_AUTH_TOKEN", "TWINE_PASSWORD", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN", "CLOUDFLARE_API_TOKEN"},
		},
		{
			profile:      "npm",
			wantKept:     []string{"NPM_TOKEN", "NODE_AUTH_TOKEN"},
			wantScrubbed: []string{"YARN_NPM_AUTH_TOKEN", "BUN_AUTH_TOKEN", "TWINE_PASSWORD", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN", "CLOUDFLARE_API_TOKEN"},
		},
		{
			profile:      "yarn",
			wantKept:     []string{"YARN_NPM_AUTH_TOKEN", "NPM_TOKEN", "NODE_AUTH_TOKEN"},
			wantScrubbed: []string{"BUN_AUTH_TOKEN", "TWINE_PASSWORD", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"},
		},
		{
			profile:      "bun",
			wantKept:     []string{"BUN_AUTH_TOKEN", "NPM_TOKEN", "NODE_AUTH_TOKEN"},
			wantScrubbed: []string{"YARN_NPM_AUTH_TOKEN", "TWINE_PASSWORD", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"},
		},
		{
			profile:      "pnpm",
			wantKept:     []string{"NPM_TOKEN", "NODE_AUTH_TOKEN"},
			wantScrubbed: []string{"YARN_NPM_AUTH_TOKEN", "BUN_AUTH_TOKEN", "TWINE_PASSWORD", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"},
		},
		{
			profile:      "npx",
			wantKept:     []string{"NPM_TOKEN", "NODE_AUTH_TOKEN"},
			wantScrubbed: []string{"YARN_NPM_AUTH_TOKEN", "BUN_AUTH_TOKEN", "TWINE_PASSWORD", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"},
		},
		{
			profile:      "pypi-restrictive",
			wantKept:     []string{},
			wantScrubbed: []string{"NPM_TOKEN", "NODE_AUTH_TOKEN", "YARN_NPM_AUTH_TOKEN", "BUN_AUTH_TOKEN", "TWINE_PASSWORD", "UV_PUBLISH_TOKEN", "POETRY_PYPI_TOKEN_PYPI", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN", "CLOUDFLARE_API_TOKEN"},
		},
		{
			profile:      "pip",
			wantKept:     []string{},
			wantScrubbed: []string{"NPM_TOKEN", "TWINE_PASSWORD", "UV_PUBLISH_TOKEN", "POETRY_PYPI_TOKEN_PYPI", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"},
		},
		{
			profile:      "pipx",
			wantKept:     []string{},
			wantScrubbed: []string{"NPM_TOKEN", "TWINE_PASSWORD", "UV_PUBLISH_TOKEN", "POETRY_PYPI_TOKEN_PYPI", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"},
		},
		{
			profile:      "uv",
			wantKept:     []string{"UV_PUBLISH_TOKEN"},
			wantScrubbed: []string{"NPM_TOKEN", "TWINE_PASSWORD", "POETRY_PYPI_TOKEN_PYPI", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"},
		},
		{
			profile:      "poetry",
			wantKept:     []string{"POETRY_PYPI_TOKEN_PYPI"},
			wantScrubbed: []string{"NPM_TOKEN", "TWINE_PASSWORD", "UV_PUBLISH_TOKEN", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.profile, func(t *testing.T) {
			policy, err := r.ResolveProfile(tt.profile, ResolveOptions{})
			require.NoError(t, err)

			result := util.ScrubEnv(env, util.EnvScrubOptions{
				Allow: policy.Environment.Allow,
				Deny:  policy.Environment.Deny,
			})

			for _, name := range tt.wantKept {
				assert.Contains(t, result.Env, name+"=x", "%s should keep %s", tt.profile, name)
			}
			for _, name := range tt.wantScrubbed {
				assert.Contains(t, result.Removed, name, "%s should scrub %s", tt.profile, name)
			}
		})
	}
}
