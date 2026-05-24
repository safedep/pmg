package sandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestRegistryFactory(t *testing.T, dir string) registryFactory {
	t.Helper()
	return func() (pmgsandbox.ProfileRegistry, error) {
		return pmgsandbox.NewProfileRegistry(pmgsandbox.WithUserProfileDir(dir))
	}
}

func runInitCmd(t *testing.T, dir string, args ...string) (string, string, error) {
	t.Helper()
	cmd := newProfileInitCommand(newTestRegistryFactory(t, dir))
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestProfileInit_HappyPath_InheritsBuiltin(t *testing.T) {
	dir := t.TempDir()

	stdout, stderr, err := runInitCmd(t, dir, "my-npm", "--from", "npm-restrictive", "--package-manager", "npm")
	require.NoError(t, err, "stderr: %s", stderr)

	expected := filepath.Join(dir, "my-npm.yml")
	assert.Equal(t, expected+"\n", stdout)

	data, err := os.ReadFile(expected)
	require.NoError(t, err)
	assert.Contains(t, string(data), "inherits: npm-restrictive")
	assert.Contains(t, string(data), "name: my-npm")
	assert.Contains(t, string(data), "- npm\n")

	// Round-trip: registry must parse and validate the new file.
	registry, err := pmgsandbox.NewProfileRegistry(pmgsandbox.WithUserProfileDir(dir))
	require.NoError(t, err)
	policy, err := registry.GetProfile("my-npm")
	require.NoError(t, err)
	assert.Equal(t, "my-npm", policy.Name)
	assert.Equal(t, []string{"npm"}, policy.PackageManagers)
}

func TestProfileInit_Standalone(t *testing.T) {
	dir := t.TempDir()

	_, stderr, err := runInitCmd(t, dir, "standalone", "--package-manager", "npm", "--description", "test profile")
	require.NoError(t, err, "stderr: %s", stderr)

	data, err := os.ReadFile(filepath.Join(dir, "standalone.yml"))
	require.NoError(t, err)
	assert.NotContains(t, string(data), "inherits:")
	assert.Contains(t, string(data), "description: test profile")

	registry, err := pmgsandbox.NewProfileRegistry(pmgsandbox.WithUserProfileDir(dir))
	require.NoError(t, err)
	policy, err := registry.GetProfile("standalone")
	require.NoError(t, err)
	assert.Equal(t, "test profile", policy.Description)
}

func TestProfileInit_DefaultPackageManager(t *testing.T) {
	dir := t.TempDir()

	_, _, err := runInitCmd(t, dir, "defaults", "--from", "npm-restrictive")
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, "defaults.yml"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "Placeholder")
	assert.Contains(t, string(data), "- npm\n")
}

func TestProfileInit_RefuseOverwrite(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "exists.yml")
	require.NoError(t, os.WriteFile(target, []byte("preexisting"), 0o644))

	_, _, err := runInitCmd(t, dir, "exists", "--from", "npm-restrictive")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
	assert.Contains(t, err.Error(), target)
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.InvalidArgument, usefulErr.Code())

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "preexisting", string(data))
}

func TestProfileInit_MissingNameShowsInstruction(t *testing.T) {
	dir := t.TempDir()

	stdout, stderr, err := runInitCmd(t, dir)
	require.Error(t, err)

	assert.Contains(t, stderr, "accepts 1 arg(s), received 0")
	assert.Contains(t, stdout, "Usage:")
	assert.Contains(t, stdout, "init <name> [flags]")
	assert.Contains(t, stdout, "Examples:")
	assert.Contains(t, stdout, "pmg sandbox profile init my-npm --from npm-restrictive")
}

func TestProfileInit_InvalidName(t *testing.T) {
	cases := []struct {
		name string
		arg  string
	}{
		{"relative traversal", "../foo"},
		{"absolute", "/abs"},
		{"space", "bad name"},
		{"leading dash", "-bad"},
		{"leading underscore", "_bad"},
		{"empty", ""},
		{"slash", "a/b"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			args := []string{"--from", "npm-restrictive", "--", tc.arg}
			if tc.arg == "" {
				// cobra ExactArgs(1) will reject the empty-name case via args
				// length, but we still want to verify rejection — pass an
				// explicit empty string as the positional arg.
				cmd := newProfileInitCommand(newTestRegistryFactory(t, dir))
				var stdout, stderr bytes.Buffer
				cmd.SetOut(&stdout)
				cmd.SetErr(&stderr)
				cmd.SetArgs([]string{""})
				err := cmd.Execute()
				require.Error(t, err)
				return
			}
			_, _, err := runInitCmd(t, dir, args...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid profile name")
			usefulErr, ok := usefulerror.AsUsefulError(err)
			require.True(t, ok)
			assert.Equal(t, errcodes.InvalidArgument, usefulErr.Code())
		})
	}
}

func TestProfileInit_UnknownBuiltin(t *testing.T) {
	dir := t.TempDir()

	_, _, err := runInitCmd(t, dir, "child", "--from", "no-such-builtin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown built-in profile")
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.NotFound, usefulErr.Code())
}

func TestProfileInit_StdoutIsExactlyThePath(t *testing.T) {
	dir := t.TempDir()
	stdout, _, err := runInitCmd(t, dir, "exact", "--from", "npm-restrictive")
	require.NoError(t, err)

	expected := filepath.Join(dir, "exact.yml") + "\n"
	assert.Equal(t, expected, stdout)
}

func TestProfileInit_CreatesMissingParentDir(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "nested", "user-profiles")

	_, _, err := runInitCmd(t, dir, "child", "--from", "npm-restrictive")
	require.NoError(t, err)

	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestProfileNameRegex(t *testing.T) {
	good := []string{"a", "A", "0", "abc", "abc-def", "abc_def", "ABC123-_x"}
	bad := []string{"", "-a", "_a", "a/b", "a b", "a.b", "..", "../x"}

	for _, s := range good {
		assert.True(t, profileNameRe.MatchString(s), "should accept %q", s)
	}
	for _, s := range bad {
		assert.False(t, profileNameRe.MatchString(s), "should reject %q", s)
	}
}

// Compile-time check that newProfileInitCommand returns *cobra.Command.
var _ = func() *cobra.Command {
	return newProfileInitCommand(func() (pmgsandbox.ProfileRegistry, error) { return nil, nil })
}

// Sanity check the rendered scaffold uses tokens the parser actually accepts.
func TestProfileInit_ScaffoldSnippet(t *testing.T) {
	dir := t.TempDir()
	_, _, err := runInitCmd(t, dir, "demo", "--from", "npm-restrictive", "--package-manager", "npm", "--description", "demo profile")
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, "demo.yml"))
	require.NoError(t, err)
	s := string(data)
	for _, want := range []string{"name: demo", "description: demo profile", "inherits: npm-restrictive", "package_managers:", "filesystem:", "network:", "process:"} {
		assert.True(t, strings.Contains(s, want), "scaffold missing %q\n--- scaffold ---\n%s", want, s)
	}
}
