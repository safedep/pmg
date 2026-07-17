package sandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const editTestProfile = `name: myprof
description: test profile
inherits: npm-restrictive
package_managers:
  - npm
filesystem:
  allow_write:
    - ${CWD}/extra
`

func writeEditTestProfile(t *testing.T, dir, name string) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path := filepath.Join(dir, name+".yml")
	require.NoError(t, os.WriteFile(path, []byte(editTestProfile), 0o644))
	return path
}

func writeEditorScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "editor.sh")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755))
	return path
}

func runEditCmd(t *testing.T, dir string, args ...string) (string, string, error) {
	t.Helper()
	cmd := newProfileEditCommand(newTestRegistryFactory(t, dir))
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestProfileEdit_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := writeEditTestProfile(t, dir, "myprof")

	editor := writeEditorScript(t, `printf '    - ${CWD}/more\n' >> "$1"`)
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", editor)

	stdout, stderr, err := runEditCmd(t, dir, "myprof")
	require.NoError(t, err, "stderr: %s", stderr)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "${CWD}/more")
	assert.Contains(t, stdout, "Profile Lint")
}

func TestProfileEdit_VisualTakesPrecedenceOverEditor(t *testing.T) {
	dir := t.TempDir()
	path := writeEditTestProfile(t, dir, "myprof")

	visual := writeEditorScript(t, `printf '    - ${CWD}/from-visual\n' >> "$1"`)
	editor := writeEditorScript(t, `printf '    - ${CWD}/from-editor\n' >> "$1"`)
	t.Setenv("VISUAL", visual)
	t.Setenv("EDITOR", editor)

	_, _, err := runEditCmd(t, dir, "myprof")
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "from-visual")
	assert.NotContains(t, string(data), "from-editor")
}

func TestProfileEdit_BuiltinRefused(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", writeEditorScript(t, `exit 0`))

	_, _, err := runEditCmd(t, dir, "npm-restrictive")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "built-in")

	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.InvalidArgument, usefulErr.Code())
	assert.Contains(t, usefulErr.Help(), "pmg sandbox profile init")
}

func TestProfileEdit_UnknownProfile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", writeEditorScript(t, `exit 0`))

	_, _, err := runEditCmd(t, dir, "no-such-profile")
	require.Error(t, err)

	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.NotFound, usefulErr.Code())
}

func TestProfileEdit_EditorFailure(t *testing.T) {
	dir := t.TempDir()
	path := writeEditTestProfile(t, dir, "myprof")

	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", writeEditorScript(t, `exit 7`))

	_, _, err := runEditCmd(t, dir, "myprof")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "editor")

	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, editTestProfile, string(data))
}

func TestProfileEdit_InvalidAfterEditKeepsFile(t *testing.T) {
	dir := t.TempDir()
	path := writeEditTestProfile(t, dir, "myprof")

	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", writeEditorScript(t, `printf 'name: [broken\n' > "$1"`))

	_, _, err := runEditCmd(t, dir, "myprof")
	require.Error(t, err)

	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.InvalidArgument, usefulErr.Code())

	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "name: [broken")
}

func TestProfileEdit_LintWarningsShown(t *testing.T) {
	dir := t.TempDir()
	writeEditTestProfile(t, dir, "myprof")

	editor := writeEditorScript(t, `printf '    - /**\n' >> "$1"`)
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", editor)

	stdout, _, err := runEditCmd(t, dir, "myprof")
	require.NoError(t, err)
	assert.Contains(t, stdout, "WARN")
}

func TestProfileEdit_ShadowedProfileWarns(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	shadow := `name: npm
package_managers:
  - npm
filesystem:
  allow_write:
    - ${CWD}/extra
`
	path := filepath.Join(dir, "npm.yml")
	require.NoError(t, os.WriteFile(path, []byte(shadow), 0o644))

	editor := writeEditorScript(t, `printf '    - ${CWD}/more\n' >> "$1"`)
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", editor)

	_, stderr, err := runEditCmd(t, dir, "npm")
	require.NoError(t, err)
	assert.Contains(t, stderr, "shadowed")

	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "${CWD}/more")
}
