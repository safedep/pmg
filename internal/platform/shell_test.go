package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"plain", "/usr/local/bin", "'/usr/local/bin'"},
		{"space", "/opt/a b/bin", "'/opt/a b/bin'"},
		{"dollar stays literal", "/opt/$HOME/bin", "'/opt/$HOME/bin'"},
		{"single quote", "a'b", `'a'\''b'`},
		{"empty", "", "''"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ShellQuote(tt.value))
		})
	}
}

func TestShellUnquoteReversesShellQuote(t *testing.T) {
	values := []string{
		"/usr/local/bin",
		"/opt/a b/bin",
		"/opt/$HOME/bin",
		"a'b'c",
		"",
	}

	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			assert.Equal(t, value, ShellUnquote(ShellQuote(value)))
		})
	}
}
