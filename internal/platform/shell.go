package platform

import "strings"

// ShellQuote wraps value in single quotes so a POSIX shell reads it literally,
// whatever spaces, $ signs, or quotes it holds. It escapes an embedded single
// quote as '\”, the form ShellUnquote reverses.
func ShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// ShellUnquote reverses ShellQuote for the single-quoted form it emits. It
// trims surrounding space first, so it reads a value back from a line a shell
// script holds.
func ShellUnquote(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "'")
	s = strings.TrimSuffix(s, "'")
	return strings.ReplaceAll(s, `'\''`, `'`)
}
