package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMergeWithParent_Environment(t *testing.T) {
	parent := &SandboxPolicy{
		Environment: EnvironmentPolicy{
			Allow: []string{"NPM_TOKEN"},
			Deny:  []string{"PARENT_SECRET"},
		},
	}
	child := &SandboxPolicy{
		Environment: EnvironmentPolicy{
			Allow: []string{"NODE_AUTH_TOKEN"},
			Deny:  []string{"CHILD_SECRET"},
		},
	}

	child.MergeWithParent(parent)

	assert.Equal(t, []string{"NPM_TOKEN", "NODE_AUTH_TOKEN"}, child.Environment.Allow)
	assert.Equal(t, []string{"PARENT_SECRET", "CHILD_SECRET"}, child.Environment.Deny)
}

// An environment-only policy is a valid policy: EnvironmentPolicy is an
// enforceable section, so it counts toward the "at least one access rule"
// check.
func TestValidateResolved_EnvironmentOnlyPolicy(t *testing.T) {
	p := &SandboxPolicy{
		Name:            "env-only",
		PackageManagers: []string{"npm"},
		Environment:     EnvironmentPolicy{Deny: []string{"*_TOKEN"}},
	}

	assert.NoError(t, p.ValidateResolved())
}

func TestResolveProfile_DeepCopiesEnvironment(t *testing.T) {
	r, err := newDefaultProfileRegistry()
	assert.NoError(t, err)

	resolved, err := r.ResolveProfile("npm", ResolveOptions{})
	assert.NoError(t, err)

	// Mutating the resolved copy must not corrupt the registry-cached policy.
	resolved.Environment.Allow = append(resolved.Environment.Allow, "MUTATED")

	again, err := r.ResolveProfile("npm", ResolveOptions{})
	assert.NoError(t, err)
	assert.NotContains(t, again.Environment.Allow, "MUTATED")
}
