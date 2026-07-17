package editor

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeScript(t *testing.T, dir, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("editor scripts require /bin/sh")
	}
	path := filepath.Join(dir, "editor.sh")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755))
	return path
}

func TestResolve_VisualWins(t *testing.T) {
	t.Setenv("VISUAL", "visual-editor")
	t.Setenv("EDITOR", "other-editor")

	editor, err := Resolve()
	require.NoError(t, err)
	assert.Equal(t, "visual-editor", editor)
}

func TestResolve_EditorFallback(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "fallback-editor")

	editor, err := Resolve()
	require.NoError(t, err)
	assert.Equal(t, "fallback-editor", editor)
}

func TestResolve_TrimsWhitespace(t *testing.T) {
	t.Setenv("VISUAL", "  vim  ")
	t.Setenv("EDITOR", "")

	editor, err := Resolve()
	require.NoError(t, err)
	assert.Equal(t, "vim", editor)
}

func TestResolve_PlatformDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix default only")
	}
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "")

	editor, err := Resolve()
	require.NoError(t, err)
	assert.Equal(t, "vi", editor)
}

func TestOpen_RunsEditorWithPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	require.NoError(t, os.WriteFile(target, []byte("before\n"), 0o644))

	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", writeScript(t, dir, `echo edited >> "$1"`))

	require.NoError(t, Open(target))

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "before\nedited\n", string(data))
}

func TestOpen_QuotedMultiWordEditor(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "dir with space")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	out := filepath.Join(base, "argv.txt")
	script := writeScript(t, dir, `printf '%s\n' "$@" > `+"'"+out+"'")

	t.Setenv("VISUAL", "'"+script+"' --wait")
	t.Setenv("EDITOR", "")

	require.NoError(t, Open("/some/target"))

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "--wait\n/some/target\n", string(data))
}

func TestOpen_EditorExitNonZero(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", writeScript(t, t.TempDir(), `exit 3`))

	err := Open("/some/target")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "editor")
}

func TestOpen_InvalidQuoting(t *testing.T) {
	t.Setenv("VISUAL", "'unterminated")
	t.Setenv("EDITOR", "")

	err := Open("/some/target")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid editor command")
}
