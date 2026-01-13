package sandbox

import (
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/stretchr/testify/assert"
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
					AllowOutbound: []string{"registry.npmjs.org:443"},
					DenyOutbound:  []string{"*:*"},
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
					AllowOutbound: []string{"github.com:443"},
					DenyOutbound:  []string{},
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

				// Still invalid because child has not name and package managers
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
			name: "missing package managers",
			policy: &SandboxPolicy{
				Name: "test",
				Filesystem: FilesystemPolicy{
					AllowRead: []string{"/usr/**"},
				},
			},
			expectErr: true,
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
