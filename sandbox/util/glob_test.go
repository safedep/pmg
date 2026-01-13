package util

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGlobToRegex(t *testing.T) {
	cases := []struct {
		name         string
		pattern      string
		shouldMatch  []string
		shouldNotMatch []string
	}{
		{
			name:    "simple asterisk wildcard",
			pattern: "/path/to/*.txt",
			shouldMatch: []string{
				"/path/to/file.txt",
				"/path/to/test.txt",
				"/path/to/a.txt",
				"/path/to/.txt", // * matches zero or more chars (standard glob behavior)
			},
			shouldNotMatch: []string{
				"/path/to/file.log",
				"/path/to/sub/file.txt",
				"/path/file.txt",
			},
		},
		{
			name:    "globstar pattern",
			pattern: "/path/**/*.txt",
			shouldMatch: []string{
				"/path/file.txt",
				"/path/to/file.txt",
				"/path/to/sub/file.txt",
				"/path/a/b/c/file.txt",
			},
			shouldNotMatch: []string{
				"/path/file.log",
				"/other/path/file.txt",
			},
		},
		{
			name:    "globstar with trailing slash",
			pattern: "/src/**/",
			shouldMatch: []string{
				"/src/",
				"/src/a/",
				"/src/a/b/",
				"/src/deep/nested/path/",
			},
			shouldNotMatch: []string{
				"/src",
				"/other/",
			},
		},
		{
			name:    "question mark wildcard",
			pattern: "/tmp/file?.log",
			shouldMatch: []string{
				"/tmp/file1.log",
				"/tmp/file2.log",
				"/tmp/filea.log",
			},
			shouldNotMatch: []string{
				"/tmp/file.log",
				"/tmp/file12.log",
				"/tmp/file/.log",
			},
		},
		{
			name:    "bracket wildcard",
			pattern: "/tmp/test[123].txt",
			shouldMatch: []string{
				"/tmp/test1.txt",
				"/tmp/test2.txt",
				"/tmp/test3.txt",
			},
			shouldNotMatch: []string{
				"/tmp/test4.txt",
				"/tmp/testa.txt",
				"/tmp/test.txt",
			},
		},
		{
			name:    "bracket range",
			pattern: "/tmp/file[0-9].log",
			shouldMatch: []string{
				"/tmp/file0.log",
				"/tmp/file5.log",
				"/tmp/file9.log",
			},
			shouldNotMatch: []string{
				"/tmp/filea.log",
				"/tmp/file10.log",
			},
		},
		{
			name:    "regex special characters escaped",
			pattern: "/path/to/file.txt",
			shouldMatch: []string{
				"/path/to/file.txt",
			},
			shouldNotMatch: []string{
				"/path/to/fileXtxt",
				"/path/to/file_txt",
			},
		},
		{
			name:    "multiple wildcards",
			pattern: "/path/*/sub/*.txt",
			shouldMatch: []string{
				"/path/a/sub/file.txt",
				"/path/b/sub/test.txt",
			},
			shouldNotMatch: []string{
				"/path/sub/file.txt",
				"/path/a/sub/deep/file.txt",
				"/path/a/b/sub/file.txt",
			},
		},
		{
			name:    "globstar in middle",
			pattern: "/usr/**/bin/node",
			shouldMatch: []string{
				"/usr/bin/node",
				"/usr/local/bin/node",
				"/usr/a/b/c/bin/node",
			},
			shouldNotMatch: []string{
				"/usr/node",
				"/usr/bin/npm",
			},
		},
		{
			name:    "exact path (no wildcards)",
			pattern: "/etc/passwd",
			shouldMatch: []string{
				"/etc/passwd",
			},
			shouldNotMatch: []string{
				"/etc/passwd.bak",
				"/etc/shadow",
			},
		},
		{
			name:    "wildcard at beginning",
			pattern: "*.txt",
			shouldMatch: []string{
				"file.txt",
				"test.txt",
			},
			shouldNotMatch: []string{
				"file.log",
				"dir/file.txt",
			},
		},
		{
			name:    "complex pattern with parens and dots",
			pattern: "/path/to/file(1).txt",
			shouldMatch: []string{
				"/path/to/file(1).txt",
			},
			shouldNotMatch: []string{
				"/path/to/file1.txt",
				"/path/to/file(1)Xtxt",
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			regexPattern := GlobToRegex(tt.pattern)
			re, err := regexp.Compile(regexPattern)
			assert.NoError(t, err, "Generated regex should be valid")

			for _, path := range tt.shouldMatch {
				assert.True(t, re.MatchString(path), "Pattern %s should match %s (regex: %s)", tt.pattern, path, regexPattern)
			}

			for _, path := range tt.shouldNotMatch {
				assert.False(t, re.MatchString(path), "Pattern %s should not match %s (regex: %s)", tt.pattern, path, regexPattern)
			}
		})
	}
}

func TestGlobToRegexPatterns(t *testing.T) {
	cases := []struct {
		name           string
		pattern        string
		expectedRegex  string
	}{
		{
			name:          "simple asterisk",
			pattern:       "*.txt",
			expectedRegex: `^[^/]*\.txt$`,
		},
		{
			name:          "globstar",
			pattern:       "**/*.txt",
			expectedRegex: `^(.*/)?[^/]*\.txt$`,
		},
		{
			name:          "question mark",
			pattern:       "file?.txt",
			expectedRegex: `^file[^/]\.txt$`,
		},
		{
			name:          "absolute path with wildcard",
			pattern:       "/path/to/*.txt",
			expectedRegex: `^/path/to/[^/]*\.txt$`,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			actual := GlobToRegex(tt.pattern)
			assert.Equal(t, tt.expectedRegex, actual)
		})
	}
}

func TestEscapeRegexChars(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "dot escaping",
			input:    "file.txt",
			expected: `file\.txt`,
		},
		{
			name:     "multiple special chars",
			input:    "file(1).txt",
			expected: `file\(1\)\.txt`,
		},
		{
			name:     "glob chars not escaped but dots are",
			input:    "*.txt",
			expected: `*\.txt`,
		},
		{
			name:     "brackets not escaped",
			input:    "[0-9]",
			expected: "[0-9]",
		},
		{
			name:     "question mark not escaped but dots are",
			input:    "file?.txt",
			expected: `file?\.txt`,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			actual := escapeRegexChars(tt.input)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestEscapeUnclosedBrackets(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "unclosed bracket at end",
			input:    "test[abc",
			expected: `test\[abc`,
		},
		{
			name:     "closed bracket",
			input:    "test[abc]",
			expected: "test[abc]",
		},
		{
			name:     "no brackets",
			input:    "test",
			expected: "test",
		},
		{
			name:     "multiple closed brackets",
			input:    "[a-z][0-9]",
			expected: "[a-z][0-9]",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			actual := escapeUnclosedBrackets(tt.input)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
