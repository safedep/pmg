package alias

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
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
