package util

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpandVariables(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Failed to get home directory: %v", err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}

	tmpDir := os.TempDir()

	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "expand HOME variable",
			input:    "${HOME}/documents",
			expected: filepath.Clean(home + "/documents"),
			wantErr:  false,
		},
		{
			name:     "expand CWD variable",
			input:    "${CWD}/files",
			expected: filepath.Clean(cwd + "/files"),
			wantErr:  false,
		},
		{
			name:     "expand TMPDIR variable",
			input:    "${TMPDIR}/cache",
			expected: filepath.Clean(tmpDir + "/cache"),
			wantErr:  false,
		},
		{
			name:     "expand multiple variables",
			input:    "${HOME}/workspace/${CWD}",
			expected: filepath.Clean(home + "/workspace/" + cwd),
			wantErr:  false,
		},
		{
			name:     "no variables to expand",
			input:    "/usr/local/bin",
			expected: filepath.Clean("/usr/local/bin"),
			wantErr:  false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: ".",
			wantErr:  false,
		},
		{
			name:     "path with parent directory references",
			input:    "${HOME}/documents/../downloads",
			expected: filepath.Clean(home + "/downloads"),
			wantErr:  false,
		},
		{
			name:     "path with current directory references",
			input:    "${HOME}/./documents",
			expected: filepath.Clean(home + "/documents"),
			wantErr:  false,
		},
		{
			name:     "all variables in one path",
			input:    "${HOME}/${CWD}/${TMPDIR}",
			expected: filepath.Clean(home + "/" + cwd + "/" + tmpDir),
			wantErr:  false,
		},
		{
			name:     "variable at end of path",
			input:    "/some/path/${HOME}",
			expected: filepath.Clean("/some/path/" + home),
			wantErr:  false,
		},
		{
			name:     "variable in middle of path",
			input:    "/prefix/${HOME}/suffix",
			expected: filepath.Clean("/prefix/" + home + "/suffix"),
			wantErr:  false,
		},
		{
			name:     "just HOME variable",
			input:    "${HOME}",
			expected: filepath.Clean(home),
			wantErr:  false,
		},
		{
			name:     "just CWD variable",
			input:    "${CWD}",
			expected: filepath.Clean(cwd),
			wantErr:  false,
		},
		{
			name:     "just TMPDIR variable",
			input:    "${TMPDIR}",
			expected: filepath.Clean(tmpDir),
			wantErr:  false,
		},
		{
			name:     "path with trailing slash",
			input:    "${HOME}/documents/",
			expected: filepath.Clean(home + "/documents"),
			wantErr:  false,
		},
		{
			name:     "relative path with variable",
			input:    "${HOME}/../other",
			expected: filepath.Clean(home + "/../other"),
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ExpandVariables(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("ExpandVariables() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && result != tt.expected {
				t.Errorf("ExpandVariables() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestContainsGlob(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		expected bool
	}{
		{
			name:     "contains asterisk wildcard",
			pattern:  "/path/to/*.txt",
			expected: true,
		},
		{
			name:     "contains question mark wildcard",
			pattern:  "/path/to/file?.txt",
			expected: true,
		},
		{
			name:     "contains bracket wildcard",
			pattern:  "/path/to/file[0-9].txt",
			expected: true,
		},
		{
			name:     "contains multiple wildcards",
			pattern:  "/path/*/file?.txt",
			expected: true,
		},
		{
			name:     "contains all wildcards",
			pattern:  "**/file?[abc].txt",
			expected: true,
		},
		{
			name:     "no wildcards",
			pattern:  "/path/to/file.txt",
			expected: false,
		},
		{
			name:     "empty string",
			pattern:  "",
			expected: false,
		},
		{
			name:     "just asterisk",
			pattern:  "*",
			expected: true,
		},
		{
			name:     "just question mark",
			pattern:  "?",
			expected: true,
		},
		{
			name:     "just bracket",
			pattern:  "[",
			expected: true,
		},
		{
			name:     "double asterisk glob",
			pattern:  "**/node_modules/**",
			expected: true,
		},
		{
			name:     "asterisk at start",
			pattern:  "*.go",
			expected: true,
		},
		{
			name:     "asterisk at end",
			pattern:  "test_*",
			expected: true,
		},
		{
			name:     "asterisk in middle",
			pattern:  "test_*_file.go",
			expected: true,
		},
		{
			name:     "bracket range",
			pattern:  "file[0-9a-z].txt",
			expected: true,
		},
		{
			name:     "path with dots but no globs",
			pattern:  "../relative/path/file.txt",
			expected: false,
		},
		{
			name:     "path with variable-like syntax but no globs",
			pattern:  "${HOME}/documents",
			expected: false,
		},
		{
			name:     "complex path without globs",
			pattern:  "/usr/local/bin/program",
			expected: false,
		},
		{
			name:     "path with spaces no globs",
			pattern:  "/path/with spaces/file.txt",
			expected: false,
		},
		{
			name:     "path with special chars but no globs",
			pattern:  "/path/with-dashes_and.dots/file.txt",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ContainsGlob(tt.pattern)
			assert.Equal(t, tt.expected, result, "ContainsGlob(%q) = %v, want %v", tt.pattern, result, tt.expected)
		})
	}
}

func TestExpandVariablesWithVariableReplacement(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		shouldContain string
		shouldReplace string
	}{
		{
			name:          "HOME gets replaced",
			input:         "${HOME}/test",
			shouldReplace: "${HOME}",
		},
		{
			name:          "CWD gets replaced",
			input:         "${CWD}/test",
			shouldReplace: "${CWD}",
		},
		{
			name:          "TMPDIR gets replaced",
			input:         "${TMPDIR}/test",
			shouldReplace: "${TMPDIR}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ExpandVariables(tt.input)

			assert.NoError(t, err, "ExpandVariables() unexpected error = %v", err)

			if tt.shouldReplace != "" && strings.Contains(result, tt.shouldReplace) {
				t.Errorf("ExpandVariables() result still contains %q, should have been replaced. Got: %v", tt.shouldReplace, result)
			}
		})
	}
}
