package shellwords

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplit(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "whitespace only",
			input: "   \t\n  ",
			want:  nil,
		},
		{
			name:  "single token",
			input: "vi",
			want:  []string{"vi"},
		},
		{
			name:  "command with flag",
			input: "code --wait",
			want:  []string{"code", "--wait"},
		},
		{
			name:  "collapses repeated whitespace",
			input: "nvim   -p \t -u  NONE",
			want:  []string{"nvim", "-p", "-u", "NONE"},
		},
		{
			name:  "leading and trailing whitespace",
			input: "  vim   ",
			want:  []string{"vim"},
		},
		{
			name:  "double-quoted path with spaces",
			input: `"/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code" --wait`,
			want: []string{
				"/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code",
				"--wait",
			},
		},
		{
			name:  "single-quoted path with spaces",
			input: `'/usr/local/bin/my editor' -f`,
			want:  []string{"/usr/local/bin/my editor", "-f"},
		},
		{
			name:  "backslash-escaped space",
			input: `/usr/local/bin/my\ editor -f`,
			want:  []string{"/usr/local/bin/my editor", "-f"},
		},
		{
			name:  "double quote inside double quotes via backslash",
			input: `code -e "say \"hi\""`,
			want:  []string{"code", "-e", `say "hi"`},
		},
		{
			name:  "single quotes inside double quotes are literal",
			input: `vim "it's fine"`,
			want:  []string{"vim", "it's fine"},
		},
		{
			name:  "double quotes inside single quotes are literal",
			input: `vim 'a "quote" here'`,
			want:  []string{"vim", `a "quote" here`},
		},
		{
			name:  "backslash inside single quotes is literal",
			input: `vim 'a\b'`,
			want:  []string{"vim", `a\b`},
		},
		{
			name:  "non-special backslash in double quotes is literal",
			input: `vim "a\b"`,
			want:  []string{"vim", `a\b`},
		},
		{
			name:  "adjacent quoted segments concatenate into one token",
			input: `vim "foo"'bar'baz`,
			want:  []string{"vim", "foobarbaz"},
		},
		{
			name:  "empty double-quoted token",
			input: `cmd "" arg`,
			want:  []string{"cmd", "", "arg"},
		},
		{
			name:  "empty single-quoted token",
			input: `cmd '' arg`,
			want:  []string{"cmd", "", "arg"},
		},
		{
			name:    "unterminated double quote",
			input:   `vim "abc`,
			wantErr: true,
		},
		{
			name:    "unterminated single quote",
			input:   `vim 'abc`,
			wantErr: true,
		},
		{
			name:    "trailing backslash outside quotes",
			input:   `vim \`,
			wantErr: true,
		},
		{
			name:    "trailing backslash inside double quotes",
			input:   `vim "abc\`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Split(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
