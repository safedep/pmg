package sandbox

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	pmgsandbox "github.com/safedep/pmg/sandbox"
)

func newTestPresetRegistry(userDir string) presetRegistryFactory {
	return func() (pmgsandbox.PresetRegistry, error) {
		opts := []pmgsandbox.PresetRegistryOption{}
		if userDir != "" {
			opts = append(opts, pmgsandbox.WithUserPresetDir(userDir))
		}
		return pmgsandbox.NewPresetRegistry(opts...)
	}
}

func writeTestUserPreset(t *testing.T, dir, name string) {
	t.Helper()
	body := `kind: preset
name: ` + name + `
description: user preset ` + name + `
metadata:
  author: Community
  labels: [custom]
filesystem:
  allow_write:
    - ${CWD}/.` + name + `/**
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, name+".yml"), []byte(body), 0o644))
}

func TestPresetListHuman(t *testing.T) {
	var out bytes.Buffer
	err := runPresetList(&out, &presetListOptions{}, newTestPresetRegistry(""))
	require.NoError(t, err)

	assert.Contains(t, out.String(), "git")
	assert.Contains(t, out.String(), "astro")
	assert.Contains(t, out.String(), "SafeDep")
	assert.Contains(t, out.String(), "pmg sandbox allow preset=")
}

func TestPresetListFilters(t *testing.T) {
	dir := t.TempDir()
	writeTestUserPreset(t, dir, "myapp")

	t.Run("label filter", func(t *testing.T) {
		var out bytes.Buffer
		err := runPresetList(&out, &presetListOptions{labels: []string{"custom"}}, newTestPresetRegistry(dir))
		require.NoError(t, err)

		assert.Contains(t, out.String(), "myapp")
		assert.NotContains(t, out.String(), "astro")
	})

	t.Run("author filter case-insensitive", func(t *testing.T) {
		var out bytes.Buffer
		err := runPresetList(&out, &presetListOptions{author: "community", jsonOut: true}, newTestPresetRegistry(dir))
		require.NoError(t, err)

		var report jsonPresetListReport
		require.NoError(t, json.Unmarshal(out.Bytes(), &report))
		require.Len(t, report.Presets, 1)
		assert.Equal(t, "myapp", report.Presets[0].Name)
		assert.Equal(t, "user", report.Presets[0].Source)
	})

	t.Run("no matches", func(t *testing.T) {
		var out bytes.Buffer
		err := runPresetList(&out, &presetListOptions{labels: []string{"nope"}}, newTestPresetRegistry(""))
		require.NoError(t, err)
		assert.Contains(t, out.String(), "No sandbox presets match")
	})
}

func TestPresetShow(t *testing.T) {
	t.Run("human output includes YAML with threat notes", func(t *testing.T) {
		var out bytes.Buffer
		err := runPresetShow(&out, "git", &presetShowOptions{}, newTestPresetRegistry(""))
		require.NoError(t, err)

		assert.Contains(t, out.String(), "Preset git (builtin)")
		assert.Contains(t, out.String(), "Threat notes")
		assert.Contains(t, out.String(), "${CWD}/.git/config")
		assert.Contains(t, out.String(), "pmg sandbox allow preset=git")
	})

	t.Run("json output includes rules", func(t *testing.T) {
		var out bytes.Buffer
		err := runPresetShow(&out, "astro", &presetShowOptions{jsonOut: true}, newTestPresetRegistry(""))
		require.NoError(t, err)

		var detail jsonPresetDetail
		require.NoError(t, json.Unmarshal(out.Bytes(), &detail))
		assert.Equal(t, "astro", detail.Name)
		assert.Contains(t, detail.Filesystem.AllowWrite, "${CWD}/.astro/**")
		assert.Contains(t, detail.Network.AllowBind, "localhost:4321")
	})

	t.Run("unknown preset is NotFound", func(t *testing.T) {
		var out bytes.Buffer
		err := runPresetShow(&out, "missing", &presetShowOptions{}, newTestPresetRegistry(""))
		require.Error(t, err)

		var useful usefulerror.UsefulError
		require.ErrorAs(t, err, &useful)
		assert.Equal(t, errcodes.NotFound, useful.Code())
	})
}

func TestPresetLint(t *testing.T) {
	dir := t.TempDir()

	valid := filepath.Join(dir, "valid.yml")
	require.NoError(t, os.WriteFile(valid, []byte(`kind: preset
name: valid
filesystem:
  allow_write: ["${CWD}/.valid/**"]
`), 0o644))

	invalid := filepath.Join(dir, "invalid.yml")
	require.NoError(t, os.WriteFile(invalid, []byte(`kind: preset
name: invalid
filesystem:
  deny_write: ["${CWD}/x"]
`), 0o644))

	t.Run("valid file passes", func(t *testing.T) {
		var out bytes.Buffer
		require.NoError(t, runPresetLint(&out, []string{valid}))
		assert.Contains(t, out.String(), "✓")
	})

	t.Run("invalid file fails with count", func(t *testing.T) {
		var out bytes.Buffer
		err := runPresetLint(&out, []string{valid, invalid})
		require.Error(t, err)
		assert.Contains(t, out.String(), "✗")
		assert.Contains(t, err.Error(), "1 of 2")
	})
}

func TestAllowPresetEntries(t *testing.T) {
	newFactory := func(t *testing.T) allowFactory {
		t.Helper()
		overlays := t.TempDir()
		return allowFactory{
			overlayDir: func() string { return overlays },
			repoRoot:   func() (string, error) { return "/repo/example", nil },
			locked:     func() bool { return false },
			presets:    newTestPresetRegistry(""),
		}
	}

	t.Run("known preset saves to overlay by reference", func(t *testing.T) {
		factory := newFactory(t)
		var out bytes.Buffer
		err := runAllow(&out, []string{"preset=git"}, &allowOptions{}, factory)
		require.NoError(t, err)
		assert.Contains(t, out.String(), "preset=git")

		overlay, _, err := pmgsandbox.LoadOverlayForRepo(factory.overlayDir(), "/repo/example")
		require.NoError(t, err)
		require.NotNil(t, overlay)
		require.Len(t, overlay.Allow, 1)
		assert.Equal(t, "git", overlay.Allow[0].Value)
	})

	t.Run("unknown preset fails at save time", func(t *testing.T) {
		factory := newFactory(t)
		var out bytes.Buffer
		err := runAllow(&out, []string{"preset=does-not-exist"}, &allowOptions{}, factory)
		require.Error(t, err)

		var useful usefulerror.UsefulError
		require.ErrorAs(t, err, &useful)
		assert.Equal(t, errcodes.NotFound, useful.Code())
	})
}

func TestPresetInit(t *testing.T) {
	newDeps := func(t *testing.T) (func() string, presetRegistryFactory) {
		t.Helper()
		dir := t.TempDir()
		return func() string { return dir }, newTestPresetRegistry(dir)
	}

	t.Run("scaffolds a valid preset that loads from the user dir", func(t *testing.T) {
		dir, factory := newDeps(t)
		var out bytes.Buffer
		err := runPresetInit(&out, "myapp", &presetInitOptions{author: "Community", labels: []string{"myapp", "dev-server"}}, dir, factory)
		require.NoError(t, err)

		target := filepath.Join(dir(), "myapp.yml")
		assert.Contains(t, out.String(), target)
		assert.Contains(t, out.String(), "preset lint")

		require.NoError(t, runPresetLint(&bytes.Buffer{}, []string{target}))

		registry, err := factory()
		require.NoError(t, err)
		info, err := registry.Get("myapp")
		require.NoError(t, err)
		assert.Equal(t, pmgsandbox.PresetSourceUser, info.Source)
		assert.Equal(t, "Community", info.Preset.Metadata.Author)
		assert.Equal(t, []string{"myapp", "dev-server"}, info.Preset.Metadata.Labels)
		assert.Contains(t, info.Preset.Filesystem.AllowWrite, "${CWD}/.myapp/**")
	})

	t.Run("refuses builtin names", func(t *testing.T) {
		dir, factory := newDeps(t)
		err := runPresetInit(&bytes.Buffer{}, "git", &presetInitOptions{}, dir, factory)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "built-in")
	})

	t.Run("refuses existing files", func(t *testing.T) {
		dir, factory := newDeps(t)
		require.NoError(t, runPresetInit(&bytes.Buffer{}, "myapp", &presetInitOptions{}, dir, factory))
		err := runPresetInit(&bytes.Buffer{}, "myapp", &presetInitOptions{}, dir, factory)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("refuses invalid names", func(t *testing.T) {
		dir, factory := newDeps(t)
		err := runPresetInit(&bytes.Buffer{}, "My_App", &presetInitOptions{}, dir, factory)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid preset name")
	})
}

func TestPresetEdit(t *testing.T) {
	setup := func(t *testing.T) (string, presetRegistryFactory) {
		t.Helper()
		dir := t.TempDir()
		factory := newTestPresetRegistry(dir)
		require.NoError(t, runPresetInit(&bytes.Buffer{}, "myapp", &presetInitOptions{}, func() string { return dir }, factory))
		return dir, factory
	}

	t.Run("valid edit passes", func(t *testing.T) {
		_, factory := setup(t)
		t.Setenv("VISUAL", "")
		t.Setenv("EDITOR", writeEditorScript(t, `exit 0`))

		var out bytes.Buffer
		require.NoError(t, runPresetEdit(&out, &bytes.Buffer{}, "myapp", factory))
		assert.Contains(t, out.String(), "✓")
	})

	t.Run("edit that breaks the preset fails validation", func(t *testing.T) {
		_, factory := setup(t)
		t.Setenv("VISUAL", "")
		t.Setenv("EDITOR", writeEditorScript(t, `printf 'kind: preset\nname: myapp\nfilesystem:\n  deny_read: ["x"]\n' > "$1"`))

		err := runPresetEdit(&bytes.Buffer{}, &bytes.Buffer{}, "myapp", factory)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "deny_read")
	})

	t.Run("builtin preset is not editable", func(t *testing.T) {
		_, factory := setup(t)
		err := runPresetEdit(&bytes.Buffer{}, &bytes.Buffer{}, "git", factory)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "built-in")
	})

	t.Run("unknown preset is not found", func(t *testing.T) {
		_, factory := setup(t)
		err := runPresetEdit(&bytes.Buffer{}, &bytes.Buffer{}, "nope", factory)
		require.Error(t, err)

		var useful usefulerror.UsefulError
		require.ErrorAs(t, err, &useful)
		assert.Equal(t, errcodes.NotFound, useful.Code())
	})

	t.Run("shadowed user preset warns", func(t *testing.T) {
		dir := t.TempDir()
		factory := newTestPresetRegistry(dir)
		writeTestUserPreset(t, dir, "git")
		t.Setenv("VISUAL", "")
		t.Setenv("EDITOR", writeEditorScript(t, `exit 0`))

		var errOut bytes.Buffer
		require.NoError(t, runPresetEdit(&bytes.Buffer{}, &errOut, "git", factory))
		assert.Contains(t, errOut.String(), "shadowed")
	})
}
