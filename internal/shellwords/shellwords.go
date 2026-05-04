// Package shellwords provides POSIX-like splitting of shell command strings
// into argv tokens. It is intentionally minimal: it handles the cases that
// arise from environment variables like $VISUAL or $EDITOR, where users may
// quote paths with spaces or pass flags. It is not a full shell parser — it
// does not perform variable expansion, command substitution, or globbing.
package shellwords

import (
	"fmt"
	"strings"
)

// Split splits s into tokens using POSIX-like rules:
//
//   - Whitespace (space, tab, newline) separates tokens.
//   - Single quotes preserve their contents verbatim; no escapes are honored.
//   - Double quotes preserve whitespace; backslash escapes only ", \, $, `.
//   - Outside quotes a backslash escapes the next character literally.
//   - Empty quoted strings ("" or '') produce an empty token.
//
// Split returns an error for unterminated quoted strings or a trailing
// backslash with nothing to escape.
func Split(s string) ([]string, error) {
	var (
		out      []string
		buf      strings.Builder
		inSingle bool
		inDouble bool
		escaped  bool
		hasToken bool
	)

	flush := func() {
		if hasToken {
			out = append(out, buf.String())
			buf.Reset()
			hasToken = false
		}
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			buf.WriteByte(c)
			hasToken = true
			escaped = false
		case inSingle:
			if c == '\'' {
				inSingle = false
			} else {
				buf.WriteByte(c)
			}
			hasToken = true
		case inDouble:
			switch c {
			case '"':
				inDouble = false
			case '\\':
				if i+1 >= len(s) {
					return nil, fmt.Errorf("dangling backslash")
				}
				next := s[i+1]
				// Inside double quotes, backslash only escapes a few
				// characters; otherwise it is literal.
				if next == '"' || next == '\\' || next == '$' || next == '`' {
					buf.WriteByte(next)
					i++
				} else {
					buf.WriteByte(c)
				}
			default:
				buf.WriteByte(c)
			}
			hasToken = true
		default:
			switch c {
			case '\'':
				inSingle = true
				hasToken = true
			case '"':
				inDouble = true
				hasToken = true
			case '\\':
				escaped = true
			case ' ', '\t', '\n':
				flush()
			default:
				buf.WriteByte(c)
				hasToken = true
			}
		}
	}

	if inSingle || inDouble {
		return nil, fmt.Errorf("unterminated quoted string")
	}
	if escaped {
		return nil, fmt.Errorf("dangling backslash")
	}
	flush()

	return out, nil
}
