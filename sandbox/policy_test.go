package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnionStringSlices(t *testing.T) {
	tests := []struct {
		name     string
		parent   []string
		child    []string
		expected []string
	}{
		{
			name:     "empty slices",
			parent:   []string{},
			child:    []string{},
			expected: []string{},
		},
		{
			name:     "parent empty, child has values",
			parent:   []string{},
			child:    []string{"a", "b"},
			expected: []string{"a", "b"},
		},
		{
			name:     "parent has values, child empty",
			parent:   []string{"a", "b"},
			child:    []string{},
			expected: []string{"a", "b"},
		},
		{
			name:     "no overlapping entries",
			parent:   []string{"a", "b"},
			child:    []string{"c", "d"},
			expected: []string{"a", "b", "c", "d"},
		},
		{
			name:     "overlapping entries (deduplication)",
			parent:   []string{"a", "b", "c"},
			child:    []string{"b", "c", "d"},
			expected: []string{"a", "b", "c", "d"},
		},
		{
			name:     "all duplicate entries",
			parent:   []string{"a", "b"},
			child:    []string{"a", "b"},
			expected: []string{"a", "b"},
		},
		{
			name:     "parent has duplicates",
			parent:   []string{"a", "a", "b"},
			child:    []string{"c"},
			expected: []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := unionStringSlices(tt.parent, tt.child)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMergeWithParent(t *testing.T) {
	cases := []struct {
		name   string
		parent *SandboxPolicy
		child  *SandboxPolicy
		assert func(t *testing.T, parent, child *SandboxPolicy)
	}{
		{
			name: "merge when all fields are present",
			parent: &SandboxPolicy{
				Name:            "parent",
				Description:     "Parent policy",
				PackageManagers: []string{"npm", "yarn"},
				AllowPTY:        utils.PtrTo(true),
				AllowGitConfig:  utils.PtrTo(false),
				Filesystem: FilesystemPolicy{
					AllowRead:  []string{"/usr/**", "/home/**"},
					AllowWrite: []string{"/tmp/**"},
					DenyRead:   []string{"/etc/shadow"},
					DenyWrite:  []string{"/etc/**"},
				},
				Network: NetworkPolicy{
					AllowOutbound:    []string{"registry.npmjs.org:443"},
					DenyOutbound:     []string{"*:*"},
					AllowUnixConnect: []string{"/run/a.sock"},
				},
				Process: ProcessPolicy{
					AllowExec: []string{"/usr/bin/node"},
					DenyExec:  []string{"/usr/bin/curl"},
				},
			},
			child: &SandboxPolicy{
				Name:            "child",
				Description:     "Child policy",
				PackageManagers: []string{"npx"},
				AllowPTY:        utils.PtrTo(false),
				AllowGitConfig:  utils.PtrTo(true),
				Filesystem: FilesystemPolicy{
					AllowRead:  []string{"/var/**"},
					AllowWrite: []string{"/home/**"},
					DenyRead:   []string{},
					DenyWrite:  []string{"/usr/**"},
				},
				Network: NetworkPolicy{
					AllowOutbound:    []string{"github.com:443"},
					DenyOutbound:     []string{},
					AllowUnixConnect: []string{"/run/b.sock", "/run/a.sock"},
				},
				Process: ProcessPolicy{
					AllowExec: []string{"/usr/bin/git"},
					DenyExec:  []string{},
				},
			},
			assert: func(t *testing.T, parent, child *SandboxPolicy) {
				// Test that name and description are preserved from child
				assert.Equal(t, "child", child.Name)
				assert.Equal(t, "Child policy", child.Description)

				// Test that package managers are replaced (not merged)
				assert.Equal(t, []string{"npx"}, child.PackageManagers)

				// Test that boolean flags are overridden
				assert.False(t, *child.AllowPTY)
				assert.True(t, *child.AllowGitConfig)

				// Test filesystem lists are unioned
				assert.ElementsMatch(t, []string{"/usr/**", "/home/**", "/var/**"}, child.Filesystem.AllowRead)
				assert.ElementsMatch(t, []string{"/tmp/**", "/home/**"}, child.Filesystem.AllowWrite)
				assert.ElementsMatch(t, []string{"/etc/shadow"}, child.Filesystem.DenyRead)
				assert.ElementsMatch(t, []string{"/etc/**", "/usr/**"}, child.Filesystem.DenyWrite)

				// Test network lists are unioned
				assert.ElementsMatch(t, []string{"registry.npmjs.org:443", "github.com:443"}, child.Network.AllowOutbound)
				assert.ElementsMatch(t, []string{"*:*"}, child.Network.DenyOutbound)
				assert.Equal(t, []string{"/run/a.sock", "/run/b.sock"}, child.Network.AllowUnixConnect)

				// Test process lists are unioned
				assert.ElementsMatch(t, []string{"/usr/bin/node", "/usr/bin/git"}, child.Process.AllowExec)
				assert.ElementsMatch(t, []string{"/usr/bin/curl"}, child.Process.DenyExec)
			},
		},
		{
			name: "merge when child has no boolean fields",
			parent: &SandboxPolicy{
				Name:            "parent",
				Description:     "Parent policy",
				PackageManagers: []string{"npm", "yarn"},
				AllowPTY:        utils.PtrTo(true),
				AllowGitConfig:  utils.PtrTo(false),
			},
			child: &SandboxPolicy{
				Filesystem: FilesystemPolicy{
					AllowRead: []string{"/usr/**"},
				},
			},
			assert: func(t *testing.T, parent, child *SandboxPolicy) {
				// Child inherits boolean fields from parent if not present in child
				assert.True(t, *child.AllowPTY)
				assert.False(t, *child.AllowGitConfig)

				// Still invalid because child has no name and package managers
				assert.Error(t, child.Validate())
				assert.Error(t, child.ValidateResolved())
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tt.child.MergeWithParent(tt.parent)
			tt.assert(t, tt.parent, tt.child)
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		policy    *SandboxPolicy
		expectErr bool
	}{
		{
			name: "valid policy without inheritance",
			policy: &SandboxPolicy{
				Name:            "test",
				PackageManagers: []string{"npm"},
				Filesystem: FilesystemPolicy{
					AllowRead: []string{"/usr/**"},
				},
			},
			expectErr: false,
		},
		{
			name: "loopback and all-interfaces bind entries are valid",
			policy: &SandboxPolicy{
				Name:    "test",
				Network: NetworkPolicy{AllowBind: []string{"127.0.0.1:5173", "[::1]:5173", "0.0.0.0:*"}},
			},
			expectErr: false,
		},
		{
			name: "a bind entry that no driver can keep is refused",
			policy: &SandboxPolicy{
				Name:    "test",
				Network: NetworkPolicy{AllowBind: []string{"192.168.1.5:3000"}},
			},
			expectErr: true,
		},
		{
			name: "absolute and variable unix socket paths are valid",
			policy: &SandboxPolicy{
				Name:    "test",
				Network: NetworkPolicy{AllowUnixConnect: []string{"/run/safedep/gryph/hook.sock", "${HOME}/.agent.sock"}},
			},
			expectErr: false,
		},
		{
			name:      "a relative unix socket path is refused",
			policy:    &SandboxPolicy{Name: "test", Network: NetworkPolicy{AllowUnixConnect: []string{"run/a.sock"}}},
			expectErr: true,
		},
		{
			name:      "an abstract unix socket name is refused",
			policy:    &SandboxPolicy{Name: "test", Network: NetworkPolicy{AllowUnixConnect: []string{"@dbus"}}},
			expectErr: true,
		},
		{
			name:      "a unix socket glob is refused",
			policy:    &SandboxPolicy{Name: "test", Network: NetworkPolicy{AllowUnixConnect: []string{"/run/*.sock"}}},
			expectErr: true,
		},
		{
			name:      "a tab in a unix socket path is refused",
			policy:    &SandboxPolicy{Name: "test", Network: NetworkPolicy{AllowUnixConnect: []string{"/run/a\t.sock"}}},
			expectErr: true,
		},
		{
			name:      "a dot component in a unix socket path is refused",
			policy:    &SandboxPolicy{Name: "test", Network: NetworkPolicy{AllowUnixConnect: []string{"/run/alias/../a.sock"}}},
			expectErr: true,
		},
		{
			name:      "a quote in a unix socket path is refused",
			policy:    &SandboxPolicy{Name: "test", Network: NetworkPolicy{AllowUnixConnect: []string{`/run/a")) (allow default`}}},
			expectErr: true,
		},
		{
			name: "missing name",
			policy: &SandboxPolicy{
				PackageManagers: []string{"npm"},
				Filesystem: FilesystemPolicy{
					AllowRead: []string{"/usr/**"},
				},
			},
			expectErr: true,
		},
		{
			name: "missing package managers is valid before the merge",
			policy: &SandboxPolicy{
				Name: "test",
				Filesystem: FilesystemPolicy{
					AllowRead: []string{"/usr/**"},
				},
			},
			expectErr: false,
		},
		{
			name: "policy with inherits but no rules is valid",
			policy: &SandboxPolicy{
				Name:            "test",
				Inherits:        "parent",
				PackageManagers: []string{"npm"},
			},
			expectErr: false, // Basic validation allows this
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateResolvedCountsDenyIPLiteralsAsARule(t *testing.T) {
	policy := &SandboxPolicy{Name: "names-only", PackageManagers: []string{"exec"}}
	assert.Error(t, policy.ValidateResolved(), "a policy with no rule is invalid")

	policy.Network.DenyIPLiterals = utils.PtrTo(true)
	assert.NoError(t, policy.ValidateResolved(), "the key is a rule: it denies every address")
}

func TestValidateResolved(t *testing.T) {
	tests := []struct {
		name      string
		policy    *SandboxPolicy
		expectErr bool
	}{
		{
			name: "valid resolved policy",
			policy: &SandboxPolicy{
				Name:            "test",
				PackageManagers: []string{"npm"},
				Filesystem: FilesystemPolicy{
					AllowRead: []string{"/usr/**"},
				},
			},
			expectErr: false,
		},
		{
			name: "resolved policy with no rules",
			policy: &SandboxPolicy{
				Name:            "test",
				PackageManagers: []string{"npm"},
			},
			expectErr: true, // Should fail because no rules after resolution
		},
		{
			name: "missing name in resolved policy",
			policy: &SandboxPolicy{
				PackageManagers: []string{"npm"},
				Filesystem: FilesystemPolicy{
					AllowRead: []string{"/usr/**"},
				},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.ValidateResolved()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMergeWithParentNetworkViaProxyOnly(t *testing.T) {
	tests := []struct {
		name     string
		parent   *bool
		child    *bool
		expected bool
	}{
		{
			name:     "child overrides parent false with true",
			parent:   utils.PtrTo(false),
			child:    utils.PtrTo(true),
			expected: true,
		},
		{
			name:     "child nil inherits parent true",
			parent:   utils.PtrTo(true),
			child:    nil,
			expected: true,
		},
		{
			name:     "both nil defaults to false",
			parent:   nil,
			child:    nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := &SandboxPolicy{NetworkViaProxyOnly: tt.parent}
			child := &SandboxPolicy{NetworkViaProxyOnly: tt.child}

			child.MergeWithParent(parent)

			assert.NotNil(t, child.NetworkViaProxyOnly)
			assert.Equal(t, tt.expected, *child.NetworkViaProxyOnly)
		})
	}
}

func TestMergeWithParentAllowDirectDNS(t *testing.T) {
	tests := []struct {
		name     string
		parent   *bool
		child    *bool
		expected bool
	}{
		{
			name:     "child overrides parent false with true",
			parent:   utils.PtrTo(false),
			child:    utils.PtrTo(true),
			expected: true,
		},
		{
			name:     "child nil inherits parent true",
			parent:   utils.PtrTo(true),
			child:    nil,
			expected: true,
		},
		{
			name:     "both nil defaults to false",
			parent:   nil,
			child:    nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := &SandboxPolicy{AllowDirectDNS: tt.parent}
			child := &SandboxPolicy{AllowDirectDNS: tt.child}

			child.MergeWithParent(parent)

			assert.NotNil(t, child.AllowDirectDNS)
			assert.Equal(t, tt.expected, *child.AllowDirectDNS)
		})
	}
}

func TestMergeWithParentAllowUnixSockets(t *testing.T) {
	tests := []struct {
		name     string
		parent   *bool
		child    *bool
		expected bool
	}{
		{"child false overrides parent true", utils.PtrTo(true), utils.PtrTo(false), false},
		{"child nil inherits parent true", utils.PtrTo(true), nil, true},
		{"both nil defaults to blocked", nil, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			child := &SandboxPolicy{AllowUnixSockets: tt.child}
			child.MergeWithParent(&SandboxPolicy{AllowUnixSockets: tt.parent})

			assert.NotNil(t, child.AllowUnixSockets)
			assert.Equal(t, tt.expected, *child.AllowUnixSockets)
		})
	}
}

func TestMergeWithParentDenyIPLiterals(t *testing.T) {
	tests := []struct {
		name     string
		parent   *bool
		child    *bool
		expected bool
	}{
		{name: "child true over parent false", parent: utils.PtrTo(false), child: utils.PtrTo(true), expected: true},
		{name: "child false over parent true", parent: utils.PtrTo(true), child: utils.PtrTo(false), expected: false},
		{name: "child nil inherits parent true", parent: utils.PtrTo(true), child: nil, expected: true},
		{name: "both nil is false", parent: nil, child: nil, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := &SandboxPolicy{Network: NetworkPolicy{DenyIPLiterals: tt.parent}}
			child := &SandboxPolicy{Network: NetworkPolicy{DenyIPLiterals: tt.child}}

			child.MergeWithParent(parent)

			assert.NotNil(t, child.Network.DenyIPLiterals)
			assert.Equal(t, tt.expected, *child.Network.DenyIPLiterals)
		})
	}
}

func TestUnixSocketRoutes(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	in := func(names ...string) string { return filepath.Join(append([]string{dir}, names...)...) }

	socket := in("real.sock")
	require.NoError(t, os.WriteFile(socket, nil, 0o600))
	require.NoError(t, os.Symlink("real.sock", in("middle.sock")))
	require.NoError(t, os.Symlink(in("middle.sock"), in("link.sock")))
	require.NoError(t, os.Symlink(in("loop.sock"), in("loop.sock")))
	require.NoError(t, os.Symlink(in(`x"y.sock`), in("unsafe.sock")))
	require.NoError(t, os.Symlink(in("host[1].sock"), in("glob.sock")))
	require.NoError(t, os.Symlink(in("${HOME}", "agent.sock"), in("variable.sock")))

	// alias/hook.sock -> ../other.sock names real/other.sock, because ".."
	// leaves the directory that alias names, not alias itself.
	require.NoError(t, os.MkdirAll(in("real", "sub"), 0o700))
	require.NoError(t, os.Symlink(in("real", "sub"), in("alias")))
	require.NoError(t, os.Symlink("../other.sock", in("real", "sub", "hook.sock")))
	require.NoError(t, os.WriteFile(in("real", "other.sock"), nil, 0o600))
	require.NoError(t, os.WriteFile(in("other.sock"), nil, 0o600))

	// a -> b -> real2 links directories. A run that replaced b would move
	// the socket that a/host.sock names.
	require.NoError(t, os.MkdirAll(in("real2"), 0o700))
	require.NoError(t, os.WriteFile(in("real2", "host.sock"), nil, 0o600))
	require.NoError(t, os.Symlink("real2", in("b")))
	require.NoError(t, os.Symlink("b", in("a")))
	require.NoError(t, os.Symlink("a/../real2/host.sock", in("dotdot.sock")))
	require.NoError(t, os.WriteFile(in("plain"), nil, 0o600))
	require.NoError(t, os.Symlink("plain/../other.sock", in("through-file.sock")))

	tests := []struct {
		name       string
		entry      string
		wantNames  []string
		wantSocket string
		wantErr    string
	}{
		{name: "a socket is its own route", entry: socket, wantNames: []string{socket}, wantSocket: socket},
		{name: "each link in the chain is a name", entry: in("link.sock"), wantNames: []string{in("link.sock"), in("middle.sock"), socket}, wantSocket: socket},
		{name: "a missing socket is a name", entry: in("none.sock"), wantNames: []string{in("none.sock")}},
		{name: "the first missing directory is a name", entry: in("none", "x.sock"), wantNames: []string{in("none", "x.sock"), in("none")}},
		{name: "a relative link below a linked directory resolves from the real directory", entry: in("alias", "hook.sock"), wantNames: []string{in("alias", "hook.sock"), in("real", "sub", "hook.sock"), in("real", "other.sock")}, wantSocket: in("real", "other.sock")},
		{name: "each linked directory is an ancestor of a name", entry: in("a", "host.sock"), wantNames: []string{in("a", "host.sock"), in("b", "host.sock"), in("real2", "host.sock")}, wantSocket: in("real2", "host.sock")},
		{name: "a file on the way ends the route without a socket", entry: in("through-file.sock"), wantNames: []string{in("through-file.sock"), in("plain")}},
		{name: "a link loop fails", entry: in("loop.sock"), wantErr: "more than"},
		{name: "a link to an invalid path fails", entry: in("unsafe.sock"), wantErr: "links to an invalid path"},
		{name: "a link to a path with a glob character fails", entry: in("glob.sock"), wantErr: "not a glob"},
		{name: "a link to a path with a variable fails", entry: in("variable.sock"), wantErr: "unexpanded variable"},
		{name: "a linked directory followed by .. fails", entry: in("dotdot.sock"), wantErr: "followed by"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &SandboxPolicy{Network: NetworkPolicy{AllowUnixConnect: []string{tt.entry}}}
			routes, err := policy.UnixSocketRoutes()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Len(t, routes, 1)
			assert.Equal(t, tt.entry, routes[0].Path)
			assert.Equal(t, tt.wantNames, routes[0].Names)
			assert.Equal(t, tt.wantSocket, routes[0].Socket)
		})
	}
}

func TestUnixConnectPaths(t *testing.T) {
	tests := []struct {
		name             string
		home             string
		allowUnixSockets *bool
		entries          []string
		want             []string
		wantErr          bool
	}{
		{name: "no entries", home: "/home/dev", want: nil},
		{name: "expands variables", home: "/home/dev", entries: []string{"/run/a.sock", "${HOME}/.b.sock"}, want: []string{"/run/a.sock", "/home/dev/.b.sock"}},
		{name: "allow_unix_sockets opens every socket", home: "/home/dev", allowUnixSockets: utils.PtrTo(true), entries: []string{"/run/a.sock"}, want: nil},
		{name: "a variable that expands to a relative path fails", home: "relative", entries: []string{"${HOME}/a.sock"}, wantErr: true},
		{name: "a glob character from a variable fails", home: "/home/[dev]", entries: []string{"${HOME}/a.sock"}, wantErr: true},
		{name: "a quote from a variable fails", home: `/home/a")`, entries: []string{"${HOME}/a.sock"}, wantErr: true},
		{name: "a dot component from a variable fails", home: "/home/alias/..", entries: []string{"${HOME}/a.sock"}, wantErr: true},
		{name: "an unknown variable fails", home: "/home/dev", entries: []string{"${NOT_A_PMG_VAR}/a.sock"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", tt.home)
			policy := &SandboxPolicy{AllowUnixSockets: tt.allowUnixSockets, Network: NetworkPolicy{AllowUnixConnect: tt.entries}}
			got, err := policy.UnixConnectPaths()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
