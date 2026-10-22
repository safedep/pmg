package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProfilePathContract pins the default paths and hosts of the built-in
// package manager profiles. Each allow fixes a common install failure, and
// each "not" or deny entry keeps a path that runs code later, or holds a
// token, out of reach. A change to one of these must be deliberate.
func TestProfilePathContract(t *testing.T) {
	r, err := newDefaultProfileRegistry()
	require.NoError(t, err)

	corepack := "${XDG_CACHE_HOME}/node/corepack/**"
	nodeGyp := []string{"${XDG_CACHE_HOME}/node-gyp/**", "${HOME}/Library/Caches/node-gyp/**"}
	userSite := "${HOME}/.local/lib/python*/**"
	releaseHosts := []string{"objects.githubusercontent.com:443", "release-assets.githubusercontent.com:443"}

	tests := []struct {
		profile       string
		inherits      string
		allowWrite    []string
		notAllowWrite []string
		denyRead      []string
		denyWrite     []string
		allowOutbound []string
	}{
		{
			profile: "pnpm",
			allowWrite: append([]string{
				"${HOME}/Library/pnpm/store/**",
				"${XDG_DATA_HOME}/pnpm/store/**",
				"${HOME}/.pnpm-state/**",
				"${XDG_STATE_HOME}/pnpm/**",
				corepack,
			}, nodeGyp...),
			// The global bin directory is on PATH.
			notAllowWrite: []string{"${HOME}/Library/pnpm/**", "${XDG_DATA_HOME}/pnpm/**"},
			allowOutbound: append([]string{"codeload.github.com:443", "nodejs.org:443"}, releaseHosts...),
		},
		{
			profile:       "yarn",
			allowWrite:    []string{"${HOME}/.yarn/berry/**", "${HOME}/Library/Caches/Yarn/**", corepack},
			allowOutbound: []string{"repo.yarnpkg.com:443"},
		},
		{
			profile:    "pnpx",
			inherits:   "npx",
			allowWrite: []string{corepack, "${CWD}/**", "${HOME}/Library/pnpm/store/**", "${XDG_DATA_HOME}/pnpm/store/**"},
		},
		{
			// Corepack does not manage npm, npx or bun by default.
			profile:       "npm",
			allowWrite:    nodeGyp,
			notAllowWrite: []string{corepack},
		},
		{profile: "npx", notAllowWrite: []string{corepack}},
		{profile: "bun", notAllowWrite: []string{corepack}},
		{
			profile:       "poetry",
			allowWrite:    []string{"${HOME}/Library/Caches/pypoetry/**"},
			notAllowWrite: []string{userSite},
		},
		{
			profile:       "uv",
			allowWrite:    []string{"${XDG_DATA_HOME}/uv/python/**"},
			notAllowWrite: []string{userSite, "${XDG_DATA_HOME}/uv/**"},
			allowOutbound: append([]string{"releases.astral.sh:443"}, releaseHosts...),
		},
		{
			profile:       "uvx",
			allowWrite:    []string{"${XDG_DATA_HOME}/uv/python/**"},
			notAllowWrite: []string{"${HOME}/.local/bin/**", "${XDG_DATA_HOME}/uv/**", userSite},
			allowOutbound: append([]string{"releases.astral.sh:443"}, releaseHosts...),
		},
		{profile: "pip", notAllowWrite: []string{userSite}},
		{
			// pipx exists to install programs, so its bin directory stays.
			profile:       "pipx",
			allowWrite:    []string{"${HOME}/.local/bin/**"},
			notAllowWrite: []string{userSite},
		},
		{
			profile:  "cargo",
			denyRead: []string{"${HOME}/.cargo/credentials.toml", "${HOME}/.cargo/credentials"},
			denyWrite: []string{
				"${HOME}/.cargo/config.toml",
				"${HOME}/.cargo/config",
				"${CWD}/.cargo/config.toml",
				"${CWD}/.cargo/config",
				"${HOME}/.cargo/env",
				"${HOME}/.cargo/env.fish",
				"${HOME}/.cargo/env.nu",
			},
			allowOutbound: []string{"static.rust-lang.org:443", "github.com:443"},
		},
		{profile: "go", allowOutbound: []string{"github.com:443"}},
	}

	for _, tt := range tests {
		t.Run(tt.profile, func(t *testing.T) {
			p, err := r.GetProfile(tt.profile)
			require.NoError(t, err)

			if tt.inherits != "" {
				assert.Contains(t, p.Lineage, tt.inherits)
			}
			for _, path := range tt.allowWrite {
				assert.Contains(t, p.Filesystem.AllowWrite, path)
			}
			for _, path := range tt.notAllowWrite {
				assert.NotContains(t, p.Filesystem.AllowWrite, path)
			}
			for _, path := range tt.denyRead {
				assert.Contains(t, p.Filesystem.DenyRead, path)
			}
			for _, path := range tt.denyWrite {
				assert.Contains(t, p.Filesystem.DenyWrite, path)
			}
			for _, host := range tt.allowOutbound {
				assert.Contains(t, p.Network.AllowOutbound, host)
			}
		})
	}
}
