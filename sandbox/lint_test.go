package sandbox

import (
	"path/filepath"
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cleanPolicy returns a minimally-valid policy with no lint issues.
func cleanPolicy() *SandboxPolicy {
	return &SandboxPolicy{
		Name:            "test",
		PackageManagers: []string{"npm"},
		Filesystem: FilesystemPolicy{
			AllowRead:  []string{"${CWD}/src/**", "${HOME}/.npmrc"},
			AllowWrite: []string{"${CWD}/dist/**"},
			DenyRead:   []string{"/etc/shadow"},
			DenyWrite:  []string{"/etc/**"},
		},
	}
}

func TestLintProfile_Clean(t *testing.T) {
	got := LintProfile(cleanPolicy())
	assert.Empty(t, got)
}

func TestLintProfile_SchemaInvalid(t *testing.T) {
	tests := []struct {
		name   string
		policy *SandboxPolicy
		want   string
	}{
		{
			name: "missing name",
			policy: &SandboxPolicy{
				PackageManagers: []string{"npm"},
				Filesystem:      FilesystemPolicy{AllowRead: []string{"/tmp"}},
			},
			want: "policy name is required",
		},
		{
			name: "no package managers",
			policy: &SandboxPolicy{
				Name:       "x",
				Filesystem: FilesystemPolicy{AllowRead: []string{"/tmp"}},
			},
			want: "at least one package manager",
		},
		{
			name: "no rules",
			policy: &SandboxPolicy{
				Name:            "x",
				PackageManagers: []string{"npm"},
			},
			want: "at least one access rule",
		},
		{
			name:   "nil",
			policy: nil,
			want:   "policy is nil",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := LintProfile(tc.policy)
			assert.NotEmpty(t, got)
			assert.Equal(t, LintLevelError, got[0].Level)
			assert.Equal(t, "schema.invalid", got[0].Code)
			assert.Contains(t, got[0].Message, tc.want)
		})
	}
}

func TestLintProfile_UnresolvedVariables(t *testing.T) {
	p := cleanPolicy()
	p.Filesystem.AllowRead = append(p.Filesystem.AllowRead, "${USER}/foo", "${HOME}/${UNKNOWN}/bar")

	got := LintProfile(p)
	codes := map[string]int{}
	for _, i := range got {
		codes[i.Code]++
	}
	assert.Equal(t, 2, codes["vars.unresolved"])

	// First unresolved should cite the rule and the field path.
	found := false
	for _, i := range got {
		if i.Code == "vars.unresolved" && i.Rule == "${USER}/foo" {
			found = true
			assert.Contains(t, i.Field, "filesystem.allow_read[")
			assert.Contains(t, i.Message, "${USER}")
		}
	}
	assert.True(t, found, "expected vars.unresolved issue for ${USER}/foo")
}

func TestLintProfile_BroadRules(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*SandboxPolicy)
		code string
	}{
		{
			name: "root glob",
			mut: func(p *SandboxPolicy) {
				p.Filesystem.AllowRead = []string{"/**"}
			},
			code: "broad.root_glob",
		},
		{
			name: "home glob",
			mut: func(p *SandboxPolicy) {
				p.Filesystem.AllowWrite = []string{"${HOME}/**"}
			},
			code: "broad.home_glob",
		},
		{
			name: "all glob",
			mut: func(p *SandboxPolicy) {
				p.Process.AllowExec = []string{"**"}
			},
			code: "broad.all_glob",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := cleanPolicy()
			tc.mut(p)
			got := LintProfile(p)
			found := false
			for _, i := range got {
				if i.Code == tc.code {
					found = true
					assert.Equal(t, LintLevelWarn, i.Level)
				}
			}
			assert.True(t, found, "expected %s issue", tc.code)
		})
	}
}

func TestLintProfile_NoBroadWarnOnDeny(t *testing.T) {
	p := cleanPolicy()
	p.Filesystem.DenyRead = []string{"/**", "${HOME}/**", "**"}
	got := LintProfile(p)
	for _, i := range got {
		assert.NotContains(t, i.Code, "broad.", "deny lists should not produce broad.* warnings")
	}
}

func TestLintProfile_ConflictAllowDeny(t *testing.T) {
	p := cleanPolicy()
	p.Filesystem.AllowRead = []string{"/etc/hosts"}
	p.Filesystem.DenyRead = []string{"/etc/hosts"}

	got := LintProfile(p)
	found := false
	for _, i := range got {
		if i.Code == "conflict.allow_deny" {
			found = true
			assert.Equal(t, LintLevelWarn, i.Level)
			assert.Equal(t, "/etc/hosts", i.Rule)
			assert.Contains(t, i.Message, "filesystem.allow_read[0]")
			assert.Contains(t, i.Message, "filesystem.deny_read[0]")
		}
	}
	assert.True(t, found)
}

func TestLintProfile_DeadShadowed(t *testing.T) {
	p := cleanPolicy()
	p.Filesystem.AllowRead = []string{
		"${HOME}/.cache/npm/**",
		"${HOME}/.cache/npm/foo",
		"${HOME}/.cache/npm/sub/**",
	}

	got := LintProfile(p)
	infoCount := 0
	for _, i := range got {
		if i.Code == "dead.shadowed" {
			infoCount++
			assert.Equal(t, LintLevelInfo, i.Level)
		}
	}
	assert.Equal(t, 2, infoCount)
}

func TestLintProfile_DeadShadowed_NoFalsePositive(t *testing.T) {
	p := cleanPolicy()
	// Sibling paths under same prefix; without /** earlier, should not shadow.
	p.Filesystem.AllowRead = []string{"${HOME}/.npmrc", "${HOME}/.npmrc.bak"}
	got := LintProfile(p)
	for _, i := range got {
		assert.NotEqual(t, "dead.shadowed", i.Code)
	}
}

func TestLintProfile_OrderingErrorsBeforeWarnsBeforeInfo(t *testing.T) {
	// Build a policy with all three classes.
	p := &SandboxPolicy{
		Name:            "x",
		PackageManagers: []string{}, // schema error
		Filesystem: FilesystemPolicy{
			AllowRead: []string{
				"/**",                       // broad warn
				"${HOME}/.cache/npm/**",     // not shadowed
				"${HOME}/.cache/npm/inside", // dead info
			},
		},
	}

	got := LintProfile(p)
	// Walk levels; must be error*, then warn*, then info*.
	phase := 0 // 0=error,1=warn,2=info
	for _, i := range got {
		switch i.Level {
		case LintLevelError:
			assert.LessOrEqual(t, phase, 0)
		case LintLevelWarn:
			if phase < 1 {
				phase = 1
			}
			assert.LessOrEqual(t, phase, 1)
		case LintLevelInfo:
			phase = 2
		}
	}
}

func TestLintProfile_AllowDirectDNSWithoutLockdown(t *testing.T) {
	tests := []struct {
		name                string
		allowDirectDNS      *bool
		networkViaProxyOnly *bool
		wantWarn            bool
	}{
		{
			name:           "allow_direct_dns without lockdown warns",
			allowDirectDNS: utils.PtrTo(true),
			wantWarn:       true,
		},
		{
			name:                "allow_direct_dns with lockdown is clean",
			allowDirectDNS:      utils.PtrTo(true),
			networkViaProxyOnly: utils.PtrTo(true),
			wantWarn:            false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := cleanPolicy()
			policy.AllowDirectDNS = tc.allowDirectDNS
			policy.NetworkViaProxyOnly = tc.networkViaProxyOnly

			var found *LintIssue
			for _, i := range LintProfile(policy) {
				if i.Code == "allow-direct-dns-without-lockdown" {
					issue := i
					found = &issue
					break
				}
			}

			if !tc.wantWarn {
				assert.Nil(t, found)
				return
			}

			require.NotNil(t, found)
			assert.Equal(t, LintLevelWarn, found.Level)
			assert.Equal(t, "allow_direct_dns", found.Field)
			assert.Equal(t, "allow_direct_dns has no effect unless network_via_proxy_only is true", found.Message)
		})
	}
}

func TestLintProfile_AllowUnixSocketsWithLockdown(t *testing.T) {
	tests := []struct {
		name                string
		networkViaProxyOnly *bool
		wantWarn            bool
	}{
		{"with lockdown warns", utils.PtrTo(true), true},
		{"without lockdown is clean", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := cleanPolicy()
			policy.AllowUnixSockets = utils.PtrTo(true)
			policy.NetworkViaProxyOnly = tc.networkViaProxyOnly

			var codes []string
			for _, i := range LintProfile(policy) {
				codes = append(codes, i.Code)
			}

			if tc.wantWarn {
				assert.Contains(t, codes, "allow-unix-sockets-with-lockdown")
			} else {
				assert.NotContains(t, codes, "allow-unix-sockets-with-lockdown")
			}
		})
	}
}

func TestLintProfile_NetworkInvalidRule(t *testing.T) {
	policy := cleanPolicy()
	policy.Network.AllowOutbound = []string{"registry.npmjs.org:443", "registry.npmjs.org"}
	policy.Network.DenyOutbound = []string{"*:*", "evil.example:https", "curl=*:*"}

	var found []LintIssue
	for _, i := range LintProfile(policy) {
		if i.Code == "network.invalid-rule" {
			found = append(found, i)
		}
	}

	require.Len(t, found, 3)
	assert.Equal(t, LintLevelError, found[0].Level)
	assert.Equal(t, "network.allow_outbound[1]", found[0].Field)
	assert.Equal(t, "registry.npmjs.org", found[0].Rule)
	assert.Contains(t, found[0].Message, "is not host:port")
	assert.Equal(t, "network.deny_outbound[1]", found[1].Field)
	assert.Contains(t, found[1].Message, "has an invalid port")
	assert.Equal(t, "network.deny_outbound[2]", found[2].Field)
	assert.Contains(t, found[2].Message, "names a client")
}

func TestLintProfile_NetworkDirectDNSBypass(t *testing.T) {
	tests := []struct {
		name     string
		rules    []string
		wantWarn bool
	}{
		{name: "rules under lockdown with direct dns warns", rules: []string{"*:*"}, wantWarn: true},
		{name: "no rules is clean", wantWarn: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := cleanPolicy()
			policy.AllowDirectDNS = utils.PtrTo(true)
			policy.NetworkViaProxyOnly = utils.PtrTo(true)
			policy.Network.DenyOutbound = tc.rules

			var found *LintIssue
			for _, i := range LintProfile(policy) {
				if i.Code == "network.direct-dns-bypass" {
					issue := i
					found = &issue
					break
				}
			}

			if !tc.wantWarn {
				assert.Nil(t, found)
				return
			}
			require.NotNil(t, found)
			assert.Equal(t, LintLevelWarn, found.Level)
			assert.Equal(t, "allow_direct_dns", found.Field)
		})
	}
}

func TestLintProfile_BuiltinNetworkRulesParse(t *testing.T) {
	registry, err := newDefaultProfileRegistry()
	require.NoError(t, err)

	summaries, err := registry.ListProfiles()
	require.NoError(t, err)
	require.NotEmpty(t, summaries)

	for _, s := range summaries {
		policy, err := registry.GetProfile(s.Name)
		require.NoError(t, err)
		for _, i := range LintProfile(policy) {
			assert.NotEqual(t, "network.invalid-rule", i.Code, "%s: %s", s.Name, i.Message)
		}
	}
}

func TestLintProfile_ConflictAcrossInheritance(t *testing.T) {
	registry, err := newDefaultProfileRegistry()
	require.NoError(t, err)

	dir := t.TempDir()
	writeProfileYAML(t, filepath.Join(dir, "base.yml"), `
name: base
description: base
package_managers: [npm]
filesystem:
  allow_read:
    - /etc/hosts
  deny_read:
    - /etc/shadow
network:
  allow_outbound:
    - registry.npmjs.org:443
`)
	leafPath := writeProfileYAML(t, filepath.Join(dir, "leaf.yml"), `
name: leaf
description: narrows the parent and re-allows a parent deny
inherits: base.yml
filesystem:
  allow_read:
    - /etc/shadow
  deny_read:
    - /etc/hosts
network:
  deny_outbound:
    - registry.npmjs.org:443
`)
	leaf, err := registry.LoadCustomProfile(leafPath)
	require.NoError(t, err)

	var conflicts []LintIssue
	for _, i := range LintProfile(leaf) {
		if i.Code == "conflict.allow_deny" {
			conflicts = append(conflicts, i)
		}
	}

	require.Len(t, conflicts, 1, "a deny of an inherited allow is not a conflict")
	assert.Equal(t, "/etc/shadow", conflicts[0].Rule)
	assert.Equal(t, "filesystem.allow_read[0]", conflicts[0].Field)
	assert.Contains(t, conflicts[0].Message, "a parent profile denies the rule")
}
