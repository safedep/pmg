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
