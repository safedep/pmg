package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// writeUserProfile writes a valid SandboxPolicy YAML named `<name>.<ext>` into
// dir. The policy is intentionally minimal but valid.
func writeUserProfile(t *testing.T, dir, name, ext string) string {
	t.Helper()

	policy := &SandboxPolicy{
		Name:            name,
		Description:     "user " + name,
		PackageManagers: []string{"npm"},
		Filesystem: FilesystemPolicy{
			AllowRead:  []string{"/tmp"},
			AllowWrite: []string{"/tmp"},
			DenyRead:   []string{"/private/var"},
			DenyWrite:  []string{"/private/var"},
		},
	}

	path := filepath.Join(dir, name+ext)
	data, err := yaml.Marshal(policy)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o644))

	return path
}

func TestListUserProfiles(t *testing.T) {
	t.Run("nil user dir returns empty", func(t *testing.T) {
		registry, err := newDefaultProfileRegistry()
		require.NoError(t, err)

		profiles, err := registry.ListUserProfiles()
		assert.NoError(t, err)
		assert.Empty(t, profiles)
		assert.Equal(t, "", registry.UserProfileDir())
	})

	t.Run("missing dir returns empty", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "does-not-exist")
		registry, err := newDefaultProfileRegistry(WithUserProfileDir(missing))
		require.NoError(t, err)

		profiles, err := registry.ListUserProfiles()
		assert.NoError(t, err)
		assert.Empty(t, profiles)
		assert.Equal(t, missing, registry.UserProfileDir())
	})

	t.Run("empty dir returns empty", func(t *testing.T) {
		dir := t.TempDir()
		registry, err := newDefaultProfileRegistry(WithUserProfileDir(dir))
		require.NoError(t, err)

		profiles, err := registry.ListUserProfiles()
		assert.NoError(t, err)
		assert.Empty(t, profiles)
	})

	t.Run("mixed yml and yaml files", func(t *testing.T) {
		dir := t.TempDir()
		writeUserProfile(t, dir, "alpha", ".yml")
		writeUserProfile(t, dir, "beta", ".yaml")
		writeUserProfile(t, dir, "gamma", ".yml")
		// non-profile files should be ignored
		require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignored"), 0o644))
		require.NoError(t, os.Mkdir(filepath.Join(dir, "subdir"), 0o755))

		registry, err := newDefaultProfileRegistry(WithUserProfileDir(dir))
		require.NoError(t, err)

		profiles, err := registry.ListUserProfiles()
		require.NoError(t, err)

		names := make([]string, 0, len(profiles))
		for _, p := range profiles {
			names = append(names, p.Name)
			assert.False(t, p.Shadowed, "user-only name should not be shadowed: %s", p.Name)
		}
		assert.ElementsMatch(t, []string{"alpha", "beta", "gamma"}, names)
	})

	t.Run("deduplicates yaml and yml by name", func(t *testing.T) {
		dir := t.TempDir()
		ymlPath := writeUserProfile(t, dir, "dupe", ".yml")
		writeUserProfile(t, dir, "dupe", ".yaml")

		registry, err := newDefaultProfileRegistry(WithUserProfileDir(dir))
		require.NoError(t, err)

		profiles, err := registry.ListUserProfiles()
		require.NoError(t, err)
		require.Len(t, profiles, 1)
		assert.Equal(t, "dupe", profiles[0].Name)
		assert.Equal(t, ymlPath, profiles[0].Path)
	})

	t.Run("user file shadowed by builtin", func(t *testing.T) {
		dir := t.TempDir()
		writeUserProfile(t, dir, "npm-restrictive", ".yml")
		writeUserProfile(t, dir, "my-custom", ".yml")

		registry, err := newDefaultProfileRegistry(WithUserProfileDir(dir))
		require.NoError(t, err)

		profiles, err := registry.ListUserProfiles()
		require.NoError(t, err)

		byName := map[string]ProfileInfo{}
		for _, p := range profiles {
			byName[p.Name] = p
		}

		require.Contains(t, byName, "npm-restrictive")
		assert.True(t, byName["npm-restrictive"].Shadowed)

		require.Contains(t, byName, "my-custom")
		assert.False(t, byName["my-custom"].Shadowed)
	})
}

func TestListProfiles(t *testing.T) {
	t.Run("builtins only", func(t *testing.T) {
		registry, err := newDefaultProfileRegistry()
		require.NoError(t, err)

		summaries, err := registry.ListProfiles()
		require.NoError(t, err)
		require.NotEmpty(t, summaries)
		for _, s := range summaries {
			assert.Equal(t, ProfileSourceBuiltin, s.Source)
			assert.Empty(t, s.Path)
			assert.False(t, s.Shadowed)
			assert.NotEmpty(t, s.PackageManagers)
			assert.NotEmpty(t, s.Description)
		}
	})

	t.Run("user only", func(t *testing.T) {
		dir := t.TempDir()
		writeUserProfile(t, dir, "alpha", ".yml")

		registry, err := newDefaultProfileRegistry(WithUserProfileDir(dir))
		require.NoError(t, err)

		summaries, err := registry.ListProfiles()
		require.NoError(t, err)

		var alpha *ProfileSummary
		for i := range summaries {
			if summaries[i].Name == "alpha" {
				alpha = &summaries[i]
				break
			}
		}
		require.NotNil(t, alpha)
		assert.Equal(t, ProfileSourceUser, alpha.Source)
		assert.NotEmpty(t, alpha.Path)
		assert.False(t, alpha.Shadowed)
		assert.Equal(t, "user alpha", alpha.Description)
		assert.Equal(t, []string{"npm"}, alpha.PackageManagers)
	})

	t.Run("mixed with shadowing", func(t *testing.T) {
		dir := t.TempDir()
		writeUserProfile(t, dir, "npm-restrictive", ".yml")
		writeUserProfile(t, dir, "my-custom", ".yml")

		registry, err := newDefaultProfileRegistry(WithUserProfileDir(dir))
		require.NoError(t, err)

		summaries, err := registry.ListProfiles()
		require.NoError(t, err)

		byKey := map[string]ProfileSummary{}
		for _, s := range summaries {
			byKey[string(s.Source)+":"+s.Name] = s
		}

		bi, ok := byKey["builtin:npm-restrictive"]
		require.True(t, ok)
		assert.False(t, bi.Shadowed)

		shadow, ok := byKey["user:npm-restrictive"]
		require.True(t, ok)
		assert.True(t, shadow.Shadowed)

		custom, ok := byKey["user:my-custom"]
		require.True(t, ok)
		assert.False(t, custom.Shadowed)
	})

	t.Run("broken yaml user file", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "broken.yml"), []byte("not: [valid"), 0o644))

		registry, err := newDefaultProfileRegistry(WithUserProfileDir(dir))
		require.NoError(t, err)

		summaries, err := registry.ListProfiles()
		require.NoError(t, err)

		var broken *ProfileSummary
		for i := range summaries {
			if summaries[i].Name == "broken" {
				broken = &summaries[i]
				break
			}
		}
		require.NotNil(t, broken)
		assert.Equal(t, ProfileSourceUser, broken.Source)
		assert.Empty(t, broken.Description)
	})
}

func TestGetProfileResolutionOrder(t *testing.T) {
	t.Run("builtin only", func(t *testing.T) {
		dir := t.TempDir()
		registry, err := newDefaultProfileRegistry(WithUserProfileDir(dir))
		require.NoError(t, err)

		policy, err := registry.GetProfile("npm-restrictive")
		require.NoError(t, err)
		assert.Equal(t, "npm-restrictive", policy.Name)
	})

	t.Run("user only by bare name", func(t *testing.T) {
		dir := t.TempDir()
		writeUserProfile(t, dir, "my-user-profile", ".yml")

		registry, err := newDefaultProfileRegistry(WithUserProfileDir(dir))
		require.NoError(t, err)

		policy, err := registry.GetProfile("my-user-profile")
		require.NoError(t, err)
		assert.Equal(t, "my-user-profile", policy.Name)
		assert.Equal(t, "user my-user-profile", policy.Description)
	})

	t.Run("user only by bare name with yaml extension", func(t *testing.T) {
		dir := t.TempDir()
		writeUserProfile(t, dir, "yaml-ext", ".yaml")

		registry, err := newDefaultProfileRegistry(WithUserProfileDir(dir))
		require.NoError(t, err)

		policy, err := registry.GetProfile("yaml-ext")
		require.NoError(t, err)
		assert.Equal(t, "yaml-ext", policy.Name)
	})

	t.Run("builtin wins when both exist", func(t *testing.T) {
		dir := t.TempDir()
		// Write a user profile whose description is unique so we can tell
		// which one was resolved.
		policy := &SandboxPolicy{
			Name:            "npm-restrictive",
			Description:     "USER VERSION",
			PackageManagers: []string{"npm"},
			Filesystem: FilesystemPolicy{
				AllowRead:  []string{"/tmp"},
				AllowWrite: []string{"/tmp"},
				DenyRead:   []string{"/private/var"},
				DenyWrite:  []string{"/private/var"},
			},
		}
		data, err := yaml.Marshal(policy)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "npm-restrictive.yml"), data, 0o644))

		registry, err := newDefaultProfileRegistry(WithUserProfileDir(dir))
		require.NoError(t, err)

		resolved, err := registry.GetProfile("npm-restrictive")
		require.NoError(t, err)
		assert.Equal(t, "npm-restrictive", resolved.Name)
		assert.NotEqual(t, "USER VERSION", resolved.Description, "builtin should win over user file of same name")
	})

	t.Run("unknown name returns error", func(t *testing.T) {
		dir := t.TempDir()
		registry, err := newDefaultProfileRegistry(WithUserProfileDir(dir))
		require.NoError(t, err)

		_, err = registry.GetProfile("no-such-profile")
		assert.Error(t, err)
	})

	t.Run("bare user profile lookup cannot escape user dir", func(t *testing.T) {
		root := t.TempDir()
		userDir := filepath.Join(root, "profiles")
		require.NoError(t, os.Mkdir(userDir, 0o755))
		outsidePath := writeUserProfile(t, root, "outside", ".yml")

		registry, err := newDefaultProfileRegistry(WithUserProfileDir(userDir))
		require.NoError(t, err)

		_, err = registry.GetProfile("../outside")
		require.Error(t, err)

		policy, err := registry.GetProfile(outsidePath)
		require.NoError(t, err)
		assert.Equal(t, "outside", policy.Name)
	})
}
