package sandbox

import (
	"testing"

	"github.com/safedep/pmg/sandbox/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProfileEnvContract pins the §2 accepted-risk trade-off as a regression
// test: each ecosystem profile re-allows its own publishing token but keeps
// other ecosystems' and cloud credentials scrubbed.
func TestProfileEnvContract(t *testing.T) {
	r, err := newDefaultProfileRegistry()
	require.NoError(t, err)

	env := []string{
		"NPM_TOKEN=x",
		"NODE_AUTH_TOKEN=x",
		"YARN_NPM_AUTH_TOKEN=x",
		"BUN_AUTH_TOKEN=x",
		"TWINE_PASSWORD=x",
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
			wantKept:     []string{"NPM_TOKEN", "NODE_AUTH_TOKEN", "YARN_NPM_AUTH_TOKEN", "BUN_AUTH_TOKEN"},
			wantScrubbed: []string{"TWINE_PASSWORD", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN", "CLOUDFLARE_API_TOKEN"},
		},
		{
			profile:      "pypi-restrictive",
			wantKept:     []string{"TWINE_PASSWORD"},
			wantScrubbed: []string{"NPM_TOKEN", "NODE_AUTH_TOKEN", "YARN_NPM_AUTH_TOKEN", "BUN_AUTH_TOKEN", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN", "CLOUDFLARE_API_TOKEN"},
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
