package sandbox

import (
	"strings"
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
// credentials. Every probe entry is on the built-in deny list, so anything
// not explicitly expected as kept must be scrubbed. This catches accidental
// over-broad environment.allow entries.
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
		profile  string
		wantKept []string
	}{
		{profile: "npm-restrictive", wantKept: []string{}},
		{profile: "pypi-restrictive", wantKept: []string{}},
		{profile: "npm", wantKept: []string{"NPM_TOKEN", "NODE_AUTH_TOKEN"}},
		{profile: "yarn", wantKept: []string{"NPM_TOKEN", "NODE_AUTH_TOKEN", "YARN_NPM_AUTH_TOKEN"}},
		{profile: "bun", wantKept: []string{"NPM_TOKEN", "NODE_AUTH_TOKEN", "BUN_AUTH_TOKEN"}},
		{profile: "pnpm", wantKept: []string{"NPM_TOKEN", "NODE_AUTH_TOKEN"}},
		{profile: "npx", wantKept: []string{"NPM_TOKEN", "NODE_AUTH_TOKEN"}},
		{profile: "pip", wantKept: []string{}},
		{profile: "pipx", wantKept: []string{}},
		{profile: "uv", wantKept: []string{"UV_PUBLISH_TOKEN"}},
		{profile: "poetry", wantKept: []string{"POETRY_PYPI_TOKEN_PYPI"}},
	}

	for _, tt := range tests {
		t.Run(tt.profile, func(t *testing.T) {
			policy, err := r.ResolveProfile(tt.profile, ResolveOptions{})
			require.NoError(t, err)

			result := util.ScrubEnv(env, util.EnvScrubOptions{
				Allow: policy.Environment.Allow,
				Deny:  policy.Environment.Deny,
			})

			kept := map[string]bool{}
			for _, name := range tt.wantKept {
				kept[name] = true
			}

			for _, entry := range env {
				name, _, _ := strings.Cut(entry, "=")
				if kept[name] {
					assert.Contains(t, result.Env, entry, "%s should keep %s", tt.profile, name)
				} else {
					assert.Contains(t, result.Removed, name, "%s should scrub %s", tt.profile, name)
				}
			}
		})
	}
}
