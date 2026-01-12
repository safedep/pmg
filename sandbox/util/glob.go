package util

import (
	"regexp"
	"strings"
)

// GlobToRegex converts a glob pattern to a Seatbelt-compatible regular expression.
//
// This implements gitignore-style pattern matching to match the behavior used
// in filesystem permission systems.
//
// Supported patterns:
//   - * matches any characters except / (e.g., *.ts matches foo.ts but not foo/bar.ts)
//   - ** matches any characters including / (e.g., src/**/*.ts matches all .ts files in src/)
//   - ? matches any single character except / (e.g., file?.txt matches file1.txt)
//   - [abc] matches any character in the set (e.g., file[0-9].txt matches file3.txt)
//
// Note: This is designed for macOS sandbox (regex ...) syntax. The resulting regex
// will be used in sandbox profiles like: (deny file-write* (regex "pattern"))
//
// Examples:
//   - "/path/to/*.txt" -> "^/path/to/[^/]*\\.txt$"
//   - "/path/**/file" -> "^/path/(.*/)?file$"
//   - "/tmp/file?.log" -> "^/tmp/file[^/]\\.log$"
func GlobToRegex(globPattern string) string {
	result := globPattern

	// Escape regex special characters (except glob chars * ? [ ])
	// We need to escape: . ^ $ + { } ( ) | \
	result = escapeRegexChars(result)

	// Escape unclosed brackets (no matching ])
	// This handles edge cases like "[abc" which should be treated literally
	result = escapeUnclosedBrackets(result)

	// Convert glob patterns to regex (order matters - ** before *)
	// Use placeholders to avoid double-conversion

	// 1. Handle **/ (globstar with slash)
	result = strings.ReplaceAll(result, "**/", "__GLOBSTAR_SLASH__")

	// 2. Handle ** (globstar standalone)
	result = strings.ReplaceAll(result, "**", "__GLOBSTAR__")

	// 3. Handle * (wildcard)
	result = strings.ReplaceAll(result, "*", "[^/]*")

	// 4. Handle ? (single char wildcard)
	result = strings.ReplaceAll(result, "?", "[^/]")

	// 5. Restore placeholders
	result = strings.ReplaceAll(result, "__GLOBSTAR_SLASH__", "(.*/)?")
	result = strings.ReplaceAll(result, "__GLOBSTAR__", ".*")

	// Add anchors for exact matching
	return "^" + result + "$"
}

// escapeRegexChars escapes regex special characters except glob wildcards.
// Escapes: . ^ $ + { } ( ) |
// Preserves: * ? [ ] \
// Note: We don't escape backslash because it shouldn't appear in file path glob patterns
func escapeRegexChars(s string) string {
	// Characters that need escaping in regex (excluding glob chars)
	// We don't include backslash here because:
	// 1. File paths on Unix don't contain backslashes
	// 2. We use backslash to escape regex chars, so escaping backslash would double them
	specialChars := []string{".", "^", "$", "+", "{", "}", "(", ")", "|"}

	result := s
	for _, char := range specialChars {
		result = strings.ReplaceAll(result, char, "\\"+char)
	}

	return result
}

var escapeUnclosedBracketsRegex = regexp.MustCompile(`\[([^\]]*?)$`)

// escapeUnclosedBrackets escapes bracket expressions that don't have a closing bracket.
// Example: "[abc" -> "\[abc"
func escapeUnclosedBrackets(s string) string {
	// Find all opening brackets that don't have a closing bracket
	return escapeUnclosedBracketsRegex.ReplaceAllString(s, `\[$1`)
}
