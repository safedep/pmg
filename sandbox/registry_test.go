package sandbox

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestNewDefaultProfileRegistry(t *testing.T) {
	registry, err := newDefaultProfileRegistry()
	assert.NoError(t, err)
	assert.NotNil(t, registry)

	assert.Greater(t, len(registry.profiles), 0)

	npmRestrictive, err := registry.GetProfile("npm-restrictive")
	assert.NoError(t, err)
	assert.NotNil(t, npmRestrictive)

	pypiRestrictive, err := registry.GetProfile("pypi-restrictive")
	assert.NoError(t, err)
	assert.NotNil(t, pypiRestrictive)
}

func TestLoadCustomProfile(t *testing.T) {
	cases := []struct {
		name   string
		policy *SandboxPolicy
		assert func(t *testing.T, policy *SandboxPolicy, err error)
	}{
		{
			name: "valid policy",
			policy: &SandboxPolicy{
				Name:            "test",
				Description:     "test",
				PackageManagers: []string{"npm"},
				// At least some rules are required for a policy to be valid
				Filesystem: FilesystemPolicy{
					AllowRead:  []string{"/tmp"},
					AllowWrite: []string{"/tmp"},
					DenyRead:   []string{"/private/var"},
					DenyWrite:  []string{"/private/var"},
				},
			},
			assert: func(t *testing.T, policy *SandboxPolicy, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, policy)
				assert.Equal(t, "test", policy.Name)
				assert.Equal(t, "test", policy.Description)
				assert.Equal(t, []string{"npm"}, policy.PackageManagers)
				assert.Equal(t, FilesystemPolicy{
					AllowRead:  []string{"/tmp"},
					AllowWrite: []string{"/tmp"},
					DenyRead:   []string{"/private/var"},
					DenyWrite:  []string{"/private/var"},
				}, policy.Filesystem)
			},
		},
		{
			name: "invalid policy without any rules",
			policy: &SandboxPolicy{
				Name:            "test",
				Description:     "test",
				PackageManagers: []string{"npm"},
			},
			assert: func(t *testing.T, policy *SandboxPolicy, err error) {
				assert.Error(t, err)
				assert.Nil(t, policy)
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			registry, err := newDefaultProfileRegistry()
			assert.NoError(t, err)
			assert.NotNil(t, registry)

			tempFile, err := os.CreateTemp(t.TempDir(), "sandbox-policy-*.yml")
			assert.NoError(t, err)
			defer tempFile.Close()

			err = yaml.NewEncoder(tempFile).Encode(c.policy)
			assert.NoError(t, err)

			policy, err := registry.LoadCustomProfile(tempFile.Name())
			c.assert(t, policy, err)
		})
	}
}

func TestBuiltinProfileInheritance(t *testing.T) {
	registry, err := newDefaultProfileRegistry()
	assert.NoError(t, err)
	assert.NotNil(t, registry)

	// Get the npx profile which inherits from npm-restrictive
	npxProfile, err := registry.GetProfile("npx")
	assert.NoError(t, err)
	assert.NotNil(t, npxProfile)

	// Verify the inherits field is cleared after resolution
	assert.Empty(t, npxProfile.Inherits)

	// Verify package managers are from child (not parent)
	assert.ElementsMatch(t, []string{"npx", "pnpx"}, npxProfile.PackageManagers)

	// Get the parent profile for comparison
	npmRestrictive, err := registry.GetProfile("npm-restrictive")
	assert.NoError(t, err)
	assert.NotNil(t, npmRestrictive)

	// Verify that child has parent's rules
	// Check that some parent rules are present
	assert.Contains(t, npxProfile.Filesystem.AllowRead, "/")
	assert.Contains(t, npxProfile.Filesystem.AllowRead, "/usr/**")
	assert.Contains(t, npxProfile.Filesystem.AllowWrite, "/tmp/**")

	// Verify that child has its own rules
	assert.Contains(t, npxProfile.Filesystem.AllowWrite, "${CWD}/**")
	assert.Contains(t, npxProfile.Filesystem.DenyWrite, "${CWD}/.env")
}

func TestLoadCustomProfileWithInheritance(t *testing.T) {
	tests := []struct {
		name   string
		policy *SandboxPolicy
		assert func(t *testing.T, policy *SandboxPolicy, err error)
	}{
		{
			name: "custom profile inherits from npm-restrictive",
			policy: &SandboxPolicy{
				Name:            "custom-npm",
				Description:     "Custom npm policy",
				Inherits:        "npm-restrictive",
				PackageManagers: []string{"npm"},
				Filesystem: FilesystemPolicy{
					AllowWrite: []string{"/custom/path/**"},
				},
			},
			assert: func(t *testing.T, policy *SandboxPolicy, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, policy)

				// Verify inheritance was resolved
				assert.Empty(t, policy.Inherits)

				// Verify parent rules are present
				assert.Contains(t, policy.Filesystem.AllowRead, "/")
				assert.Contains(t, policy.Filesystem.AllowRead, "/usr/**")

				// Verify child rules are added
				assert.Contains(t, policy.Filesystem.AllowWrite, "/custom/path/**")
				assert.Contains(t, policy.Filesystem.AllowWrite, "/tmp/**")
			},
		},
		{
			name: "custom profile inherits from already-resolved profile (npx)",
			policy: &SandboxPolicy{
				Name:            "custom-chain",
				Description:     "Inherits from npx which already resolved its inheritance",
				Inherits:        "npx",
				PackageManagers: []string{"npm"},
				Filesystem: FilesystemPolicy{
					AllowWrite: []string{"/custom/**"},
				},
			},
			assert: func(t *testing.T, policy *SandboxPolicy, err error) {
				// This should succeed because npx has already resolved its inheritance
				// and no longer has an Inherits field set
				assert.NoError(t, err)
				assert.NotNil(t, policy)
				assert.Empty(t, policy.Inherits)
			},
		},
		{
			name: "custom profile inherits from non-existent profile",
			policy: &SandboxPolicy{
				Name:            "custom-bad",
				Description:     "Should fail",
				Inherits:        "does-not-exist",
				PackageManagers: []string{"npm"},
			},
			assert: func(t *testing.T, policy *SandboxPolicy, err error) {
				// This should fail because parent doesn't exist
				assert.Error(t, err)
				assert.Nil(t, policy)
				assert.Contains(t, err.Error(), "inherits from unknown profile")
			},
		},
		{
			name: "custom profile with multiple inherited and own rules",
			policy: &SandboxPolicy{
				Name:            "custom-extended",
				Description:     "Extended npm profile",
				Inherits:        "npm-restrictive",
				PackageManagers: []string{"npm", "yarn"},
				Filesystem: FilesystemPolicy{
					AllowRead:  []string{"/opt/**"},
					AllowWrite: []string{"/data/**", "/cache/**"},
					DenyWrite:  []string{"/data/secrets/**"},
				},
				Network: NetworkPolicy{
					AllowOutbound: []string{"custom.registry.io:443"},
				},
			},
			assert: func(t *testing.T, policy *SandboxPolicy, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, policy)

				// Verify inheritance resolved
				assert.Empty(t, policy.Inherits)

				// Verify parent and child filesystem rules are merged
				assert.Contains(t, policy.Filesystem.AllowRead, "/")
				assert.Contains(t, policy.Filesystem.AllowRead, "/usr/**")
				assert.Contains(t, policy.Filesystem.AllowRead, "/opt/**")
				assert.Contains(t, policy.Filesystem.AllowWrite, "/tmp/**")
				assert.Contains(t, policy.Filesystem.AllowWrite, "/data/**")
				assert.Contains(t, policy.Filesystem.AllowWrite, "/cache/**")
				assert.Contains(t, policy.Filesystem.DenyWrite, "/etc/**")
				assert.Contains(t, policy.Filesystem.DenyWrite, "/data/secrets/**")

				// Verify network rules are merged
				assert.Contains(t, policy.Network.AllowOutbound, "registry.npmjs.org:443")
				assert.Contains(t, policy.Network.AllowOutbound, "custom.registry.io:443")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, err := newDefaultProfileRegistry()
			assert.NoError(t, err)
			assert.NotNil(t, registry)

			tempFile, err := os.CreateTemp(t.TempDir(), "custom-policy-*.yml")
			assert.NoError(t, err)
			defer tempFile.Close()

			err = yaml.NewEncoder(tempFile).Encode(tt.policy)
			assert.NoError(t, err)

			loadedPolicy, err := registry.LoadCustomProfile(tempFile.Name())
			tt.assert(t, loadedPolicy, err)
		})
	}
}

func TestResolveInheritance(t *testing.T) {
	registry, err := newDefaultProfileRegistry()
	assert.NoError(t, err)
	assert.NotNil(t, registry)

	parent := &SandboxPolicy{
		Name:            "test-parent",
		PackageManagers: []string{"npm"},
		Filesystem: FilesystemPolicy{
			AllowRead:  []string{"/parent/**"},
			AllowWrite: []string{"/parent/write/**"},
		},
	}

	child := &SandboxPolicy{
		Name:            "test-child",
		Inherits:        "test-parent",
		PackageManagers: []string{"npx"},
		Filesystem: FilesystemPolicy{
			AllowRead:  []string{"/child/**"},
			AllowWrite: []string{"/child/write/**"},
		},
	}

	// Add parent to registry
	registry.mu.Lock()
	registry.profiles["test-parent"] = parent
	registry.mu.Unlock()

	// Resolve inheritance
	registry.mu.Lock()
	err = registry.resolveInheritance(child)
	registry.mu.Unlock()

	assert.NoError(t, err)
	assert.Empty(t, child.Inherits)

	// Verify lists are merged
	assert.ElementsMatch(t, []string{"/parent/**", "/child/**"}, child.Filesystem.AllowRead)
	assert.ElementsMatch(t, []string{"/parent/write/**", "/child/write/**"}, child.Filesystem.AllowWrite)

	// Verify package managers are from child
	assert.Equal(t, []string{"npx"}, child.PackageManagers)
}
