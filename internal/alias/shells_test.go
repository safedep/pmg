package alias

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShellPathExport(t *testing.T) {
	tests := []struct {
		name     string
		shell    Shell
		binDir   string
		contains []string
	}{
		{
			name:   "bash path export",
			shell:  &bashShell{},
			binDir: "/home/user/.pmg/bin",
			contains: []string{
				`export PATH="/home/user/.pmg/bin:$PATH"`,
				"PMG shims",
			},
		},
		{
			name:   "zsh path export",
			shell:  &zshShell{},
			binDir: "/home/user/.pmg/bin",
			contains: []string{
				`export PATH="/home/user/.pmg/bin:$PATH"`,
				"PMG shims",
			},
		},
		{
			name:   "fish path export",
			shell:  &fishShell{},
			binDir: "/home/user/.pmg/bin",
			contains: []string{
				`fish_add_path --prepend "/home/user/.pmg/bin"`,
				"PMG shims",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.shell.PathExport(tc.binDir)
			for _, s := range tc.contains {
				assert.Contains(t, result, s)
			}
		})
	}
}

func TestPrimaryShellName(t *testing.T) {
	t.Run("from SHELL", func(t *testing.T) {
		t.Setenv("SHELL", "/usr/bin/fish")
		assert.Equal(t, "fish", PrimaryShellName())
	})

	t.Run("falls back to OS default when unset", func(t *testing.T) {
		t.Setenv("SHELL", "")
		want := "bash"
		if runtime.GOOS == "darwin" {
			want = "zsh"
		}
		assert.Equal(t, want, PrimaryShellName())
	})
}

func TestBashInstallRcFiles(t *testing.T) {
	const (
		bashrc      = ".bashrc"
		bashProfile = ".bash_profile"
		profile     = ".profile"
	)

	tests := []struct {
		name     string
		goos     string
		create   bool
		existing map[string]string
		wantRel  []string
		wantMade []string
	}{
		{
			name:     "darwin bashrc only, primary also creates bash_profile",
			goos:     "darwin",
			create:   true,
			existing: map[string]string{bashrc: "# bashrc\n"},
			wantRel:  []string{bashrc, bashProfile},
			wantMade: []string{bashProfile},
		},
		{
			name:     "darwin login already sources bashrc is skipped",
			goos:     "darwin",
			create:   true,
			existing: map[string]string{bashrc: "# bashrc\n", bashProfile: "source ~/.bashrc\n"},
			wantRel:  []string{bashrc},
		},
		{
			name:     "darwin login not sourcing bashrc gets both",
			goos:     "darwin",
			create:   true,
			existing: map[string]string{bashrc: "# bashrc\n", bashProfile: "# profile\n"},
			wantRel:  []string{bashrc, bashProfile},
		},
		{
			name:     "darwin login only mentions bashrc in a comment gets both",
			goos:     "darwin",
			create:   true,
			existing: map[string]string{bashrc: "# bashrc\n", bashProfile: "# see ~/.bashrc\n"},
			wantRel:  []string{bashrc, bashProfile},
		},
		{
			name:     "darwin nothing exists, primary creates bash_profile",
			goos:     "darwin",
			create:   true,
			existing: map[string]string{},
			wantRel:  []string{bashProfile},
			wantMade: []string{bashProfile},
		},
		{
			name:     "darwin nothing exists, non-primary creates nothing",
			goos:     "darwin",
			create:   false,
			existing: map[string]string{},
			wantRel:  nil,
		},
		{
			name:     "linux bashrc only does not create bash_profile",
			goos:     "linux",
			create:   true,
			existing: map[string]string{bashrc: "# bashrc\n"},
			wantRel:  []string{bashrc},
		},
		{
			name:     "linux nothing exists, primary creates bashrc",
			goos:     "linux",
			create:   true,
			existing: map[string]string{},
			wantRel:  []string{bashrc},
			wantMade: []string{bashrc},
		},
		{
			name:     "existing login file wired even when non-primary",
			goos:     "linux",
			create:   false,
			existing: map[string]string{profile: "# profile\n"},
			wantRel:  []string{profile},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			for name, content := range tc.existing {
				require.NoError(t, os.WriteFile(filepath.Join(home, name), []byte(content), 0o644))
			}

			got, err := bashInstallRcFiles(home, tc.create, tc.goos)
			require.NoError(t, err)

			want := make([]string, 0, len(tc.wantRel))
			for _, rel := range tc.wantRel {
				want = append(want, filepath.Join(home, rel))
			}
			assert.ElementsMatch(t, want, got)

			for _, rel := range tc.wantMade {
				assert.FileExists(t, filepath.Join(home, rel))
			}
		})
	}
}

func TestReferencesBashrc(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"source with tilde", "source ~/.bashrc\n", true},
		{"dot command", ". ~/.bashrc\n", true},
		{"quoted home var", "[ -f \"$HOME/.bashrc\" ] && source \"$HOME/.bashrc\"\n", true},
		{"conditional dot", "[ -f ~/.bashrc ] && . ~/.bashrc\n", true},
		{"commented mention", "# see ~/.bashrc for details\n", false},
		{"inline comment", "echo hi # ~/.bashrc\n", false},
		{"unrelated command", "cat ~/.bashrc\n", false},
		{"different file", "source ~/.bashrc-backup\n", false},
		{"no mention", "export PATH=/usr/bin\n", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "profile")
			require.NoError(t, os.WriteFile(path, []byte(tc.content), 0o644))
			assert.Equal(t, tc.want, referencesBashrc(path))
		})
	}
}

func TestRewriteFileDroppingLines(t *testing.T) {
	t.Run("drops matching lines and keeps the rest", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "rc")
		require.NoError(t, os.WriteFile(path, []byte("keep1\ndrop me\nkeep2\n"), 0o644))

		err := RewriteFileDroppingLines(path, func(line string) bool {
			return strings.Contains(line, "drop")
		})
		require.NoError(t, err)

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "keep1\nkeep2\n", string(data))

		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
	})

	t.Run("preserves a line longer than the scanner token limit", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "rc")
		longLine := strings.Repeat("x", bufio.MaxScanTokenSize+1024)
		require.NoError(t, os.WriteFile(path, []byte(longLine+"\nPMG drop\nafter\n"), 0o644))

		err := RewriteFileDroppingLines(path, func(line string) bool {
			return strings.Contains(line, "PMG drop")
		})
		require.NoError(t, err)

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, longLine+"\nafter\n", string(data))
	})

	t.Run("leaves the file untouched when nothing matches", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "rc")
		original := "line1\nline2"
		require.NoError(t, os.WriteFile(path, []byte(original), 0o644))

		err := RewriteFileDroppingLines(path, func(string) bool { return false })
		require.NoError(t, err)

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, original, string(data))
	})

	t.Run("missing file is a no-op", func(t *testing.T) {
		err := RewriteFileDroppingLines(filepath.Join(t.TempDir(), "nope"), func(string) bool { return true })
		assert.NoError(t, err)
	})
}

func TestDetectShell(t *testing.T) {
	cases := []struct {
		name          string
		shellEnvValue string
		want          string
		wantErr       error
	}{
		{
			name:          "bash full path",
			shellEnvValue: "/bin/bash",
			want:          "bash",
			wantErr:       nil,
		},
		{
			name:          "zsh full path",
			shellEnvValue: "/bin/zsh",
			want:          "zsh",
			wantErr:       nil,
		},
		{
			name:          "bash only name",
			shellEnvValue: "bash",
			want:          "bash",
			wantErr:       nil,
		},
		{
			name:          "when shell env is not set",
			shellEnvValue: "",
			want:          "",
			wantErr:       fmt.Errorf("SHELL environment variable not set"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SHELL", tc.shellEnvValue)
			got, err := DetectShell()

			if tc.wantErr != nil {
				assert.ErrorContains(t, err, tc.wantErr.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}
